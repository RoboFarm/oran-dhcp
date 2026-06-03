"""Pure-stdlib reader for capture files (classic pcap + minimal pcapng).

This module parses packet capture files without any third-party dependency
(no scapy/dpkt/tshark). It understands two on-disk container formats:

* Classic libpcap ("pcap") -- see the de-facto spec at
  https://wiki.wireshark.org/Development/LibpcapFileFormat and
  https://datatracker.ietf.org/doc/html/draft-gharris-opsawg-pcap.
  A 24-byte global header begins with a 32-bit magic number that selects
  byte order AND timestamp resolution:
      0xa1b2c3d4 -> big-endian,    microsecond timestamps
      0xd4c3b2a1 -> little-endian, microsecond timestamps
      0xa1b23c4d -> big-endian,    nanosecond timestamps
      0x4d3cb2a1 -> little-endian, nanosecond timestamps
  Each record then has a 16-byte header: ts_sec, ts_frac, incl_len, orig_len.

* PCAP Next Generation ("pcapng") -- see
  https://datatracker.ietf.org/doc/html/draft-tuexen-opsawg-pcapng.
  Block-structured; the first block is a Section Header Block whose magic is
  0x0a0d0d0a. We do a best-effort walk of SHB / IDB / EPB (and the legacy
  Simple Packet Block) to recover frames and per-interface link types.

Link-layer decoding currently supports LINKTYPE_ETHERNET (1, "EN10MB").
For each Ethernet frame we strip up to two 802.1Q / 802.1ad VLAN tags
(0x8100 / 0x88a8), record the inner VLAN id, and decode IPv4 (0x0800),
IPv6 (0x86dd) and UDP (protocol 17) payloads.

Robustness contract: every per-record parse is wrapped in try/except and a
malformed or truncated record is SKIPPED rather than raising, so a damaged
tail never loses the records that preceded it.
"""

import struct
from typing import List, Optional, Tuple

from .models import CapturedPacket

# Ethertypes / link constants ------------------------------------------------
ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
VLAN_TPIDS = (ETH_P_8021Q, ETH_P_8021AD)

LINKTYPE_ETHERNET = 1

# Classic pcap global-header magics: value -> (struct byte-order, ts divisor)
_PCAP_MAGICS = {
    0xA1B2C3D4: (">", 1_000_000),       # big-endian, microsecond
    0xD4C3B2A1: ("<", 1_000_000),       # little-endian, microsecond
    0xA1B23C4D: (">", 1_000_000_000),   # big-endian, nanosecond
    0x4D3CB2A1: ("<", 1_000_000_000),   # little-endian, nanosecond
}

# pcapng block-type / magic constants
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006
_PCAPNG_SPB = 0x00000003


def _mac(b: bytes) -> str:
    """Format 6 raw bytes as a lowercase colon-separated MAC address."""
    return ":".join("%02x" % x for x in b[:6])


def _ipv4(b: bytes) -> str:
    """Format 4 raw bytes as dotted-quad."""
    return ".".join(str(x) for x in b[:4])


def _ipv6(b: bytes) -> str:
    """Format 16 raw bytes as a (non-compressed) colon-grouped IPv6 string."""
    return ":".join("%02x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2))


def read_pcap(path: str) -> List[CapturedPacket]:
    """Read *path* and return a list of :class:`CapturedPacket`.

    Auto-detects classic pcap (either endianness, microsecond or nanosecond
    resolution) and best-effort pcapng. Malformed/truncated records are
    skipped, never raised.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 4:
        return []

    head = data[:4]
    # pcapng Section Header Block starts with the byte-order magic 0x0a0d0d0a
    # regardless of endianness.
    if head == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(data)
    if head == struct.pack(">I", _PCAPNG_SHB) or head == struct.pack("<I", _PCAPNG_SHB):
        return _read_pcapng(data)

    # Classic pcap: try both endiannesses of the magic.
    magic_be = struct.unpack(">I", head)[0]
    magic_le = struct.unpack("<I", head)[0]
    if magic_be in _PCAP_MAGICS:
        endian, divisor = _PCAP_MAGICS[magic_be]
        return _read_classic(data, endian, divisor)
    if magic_le in _PCAP_MAGICS:
        endian, divisor = _PCAP_MAGICS[magic_le]
        return _read_classic(data, endian, divisor)

    return []


def _read_classic(data: bytes, endian: str, divisor: int) -> List[CapturedPacket]:
    """Parse a classic libpcap stream given byte order and timestamp divisor."""
    packets: List[CapturedPacket] = []
    if len(data) < 24:
        return packets
    # Global header: magic(4) ver_major(2) ver_minor(2) thiszone(4)
    # sigfigs(4) snaplen(4) network/linktype(4)
    try:
        linktype = struct.unpack(endian + "I", data[20:24])[0]
    except struct.error:
        linktype = LINKTYPE_ETHERNET

    off = 24
    index = 0
    n = len(data)
    while off + 16 <= n:
        try:
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                endian + "IIII", data[off:off + 16]
            )
        except struct.error:
            break
        rec_start = off + 16
        rec_end = rec_start + incl_len
        if incl_len == 0 or rec_end > n:
            # Truncated final record -- stop cleanly.
            break
        frame = data[rec_start:rec_end]
        off = rec_end
        ts = ts_sec + (ts_frac / divisor)
        try:
            pkt = _decode_frame(index, ts, frame, linktype)
        except Exception:
            pkt = None
        if pkt is not None:
            packets.append(pkt)
            index += 1
    return packets


def _read_pcapng(data: bytes) -> List[CapturedPacket]:
    """Best-effort pcapng walk: SHB establishes endianness; IDB records link
    types; EPB/SPB carry frames."""
    packets: List[CapturedPacket] = []
    n = len(data)
    off = 0
    endian = "<"
    interfaces: List[int] = []  # interface_id -> linktype
    index = 0

    while off + 8 <= n:
        block_type_raw = data[off:off + 4]
        # The SHB carries the byte-order magic in its body; detect endianness
        # from it the first time we see one.
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            # Byte-order magic lives at body offset 8.
            if off + 12 <= n:
                bom = data[off + 8:off + 12]
                if bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
            block_type = _PCAPNG_SHB
        else:
            try:
                block_type = struct.unpack(endian + "I", block_type_raw)[0]
            except struct.error:
                break

        # Generic block layout: type(4) total_len(4) body... total_len(4)
        try:
            total_len = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        except struct.error:
            break
        if total_len < 12 or off + total_len > n:
            break
        body = data[off + 8:off + total_len - 4]

        try:
            if block_type == _PCAPNG_IDB:
                # Interface Description Block: linktype(2) reserved(2) snaplen(4)
                linktype = struct.unpack(endian + "H", body[0:2])[0]
                interfaces.append(linktype)
            elif block_type == _PCAPNG_EPB:
                # Enhanced Packet Block: if_id(4) ts_high(4) ts_low(4)
                # cap_len(4) orig_len(4) packet...
                if_id, ts_high, ts_low, cap_len, _orig = struct.unpack(
                    endian + "IIIII", body[0:20]
                )
                frame = body[20:20 + cap_len]
                linktype = interfaces[if_id] if if_id < len(interfaces) else LINKTYPE_ETHERNET
                ts = ((ts_high << 32) | ts_low) / 1_000_000.0
                pkt = _decode_frame(index, ts, frame, linktype)
                if pkt is not None:
                    packets.append(pkt)
                    index += 1
            elif block_type == _PCAPNG_SPB:
                # Simple Packet Block: orig_len(4) packet... (capped by block).
                _orig = struct.unpack(endian + "I", body[0:4])[0]
                frame = body[4:]
                linktype = interfaces[0] if interfaces else LINKTYPE_ETHERNET
                pkt = _decode_frame(index, 0.0, frame, linktype)
                if pkt is not None:
                    packets.append(pkt)
                    index += 1
        except Exception:
            pass  # skip a malformed block but keep walking

        off += total_len

    return packets


def _decode_frame(index: int, ts: float, frame: bytes, linktype: int) -> Optional[CapturedPacket]:
    """Decode one captured frame into a CapturedPacket.

    Only LINKTYPE_ETHERNET (1) is interpreted at L2/L3/L4; other link types
    still yield a packet record with raw bytes preserved.
    """
    if linktype != LINKTYPE_ETHERNET:
        return CapturedPacket(
            index=index, ts=ts, eth_src="", eth_dst="", ethertype=0,
            vlan=None, l3="other", src_ip=None, dst_ip=None,
            l4=None, src_port=None, dst_port=None, payload=b"", raw=frame,
        )

    if len(frame) < 14:
        return None

    eth_dst = _mac(frame[0:6])
    eth_src = _mac(frame[6:12])
    ethertype = struct.unpack(">H", frame[12:14])[0]
    p = 14
    vlan: Optional[int] = None

    # Strip up to two stacked VLAN tags (QinQ); record the INNER vlan id and
    # set ethertype to the innermost encapsulated type.
    tags = 0
    while ethertype in VLAN_TPIDS and tags < 2 and p + 4 <= len(frame):
        tci = struct.unpack(">H", frame[p:p + 2])[0]
        vlan = tci & 0x0FFF
        ethertype = struct.unpack(">H", frame[p + 2:p + 4])[0]
        p += 4
        tags += 1

    l3 = "other"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    l4: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload = b""

    if ethertype == ETH_P_IPV4:
        l3 = "ipv4"
        if p + 20 <= len(frame):
            ver_ihl = frame[p]
            ihl = (ver_ihl & 0x0F) * 4
            if ihl >= 20 and p + ihl <= len(frame):
                proto = frame[p + 9]
                src_ip = _ipv4(frame[p + 12:p + 16])
                dst_ip = _ipv4(frame[p + 16:p + 20])
                l4_off = p + ihl
                if proto == 17:  # UDP
                    l4, src_port, dst_port, payload = _parse_udp(frame, l4_off)
    elif ethertype == ETH_P_IPV6:
        l3 = "ipv6"
        if p + 40 <= len(frame):
            next_hdr = frame[p + 6]
            src_ip = _ipv6(frame[p + 8:p + 24])
            dst_ip = _ipv6(frame[p + 24:p + 40])
            l4_off = p + 40
            # Walk past common IPv6 extension headers (hop-by-hop=0,
            # routing=43, dest-opts=60) to reach the upper-layer protocol.
            while next_hdr in (0, 43, 60) and l4_off + 2 <= len(frame):
                ext_next = frame[l4_off]
                ext_len = (frame[l4_off + 1] + 1) * 8
                l4_off += ext_len
                next_hdr = ext_next
            if next_hdr == 17:  # UDP
                l4, src_port, dst_port, payload = _parse_udp(frame, l4_off)

    return CapturedPacket(
        index=index, ts=ts, eth_src=eth_src, eth_dst=eth_dst, ethertype=ethertype,
        vlan=vlan, l3=l3, src_ip=src_ip, dst_ip=dst_ip,
        l4=l4, src_port=src_port, dst_port=dst_port, payload=payload, raw=frame,
    )


def _parse_udp(frame: bytes, off: int) -> Tuple[Optional[str], Optional[int], Optional[int], bytes]:
    """Parse a UDP header at *off*; return (l4, src_port, dst_port, payload).

    Returns ('udp', None, None, b'') sentinel-style values when the 8-byte
    UDP header does not fit; payload is everything after that header, clamped
    to the captured frame length.
    """
    if off + 8 > len(frame):
        return None, None, None, b""
    src_port, dst_port, ulen, _csum = struct.unpack(">HHHH", frame[off:off + 8])
    payload_start = off + 8
    # Honor the UDP length field but never read past the captured bytes.
    if ulen >= 8:
        payload_end = off + ulen
    else:
        payload_end = len(frame)
    payload_end = min(payload_end, len(frame))
    payload = frame[payload_start:payload_end]
    return "udp", src_port, dst_port, payload
