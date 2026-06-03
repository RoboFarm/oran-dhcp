#!/usr/bin/env python3
"""
make_fixtures.py -- deterministic test-fixture generator for dhcp-oru-toolkit.

Regenerates, byte-for-byte idempotently, every fixture consumed by the test
suite and the demo targets. Pure Python standard library only: no scapy/dpkt,
no third-party imports, no network, no wall-clock calls. Every timestamp is
derived from FIXED integer epoch constants defined in this module, so repeated
runs produce identical files.

Fixtures written under tests/fixtures/:

  oru_xid_reuse.pcap   Classic little-endian microsecond pcap (linktype 1,
                       EN10MB) that reproduces EXACTLY the two transaction-id
                       reuse sequences from the Fujitsu O-RU bug report:
                       Seq#1 xid 0x8fc37a94, Seq#2 xid 0xcb07f611. Frames are
                       802.1Q (VLAN 201) Ethernet / IPv4 / UDP BOOTP-DHCP
                       broadcasts. Client messages go 68->67, server messages
                       67->68; src 0.0.0.0 (clients) or .1 (server) towards
                       255.255.255.255. Each client packet carries opt53 type,
                       opt60 vendor-class ("o-ran-ru2/FJ/...") and -- crucially
                       -- NO opt61 client-id. The shared xid plus three O-RUs
                       racing for the same offered IP is the defect under test.

  clean_dhcp.pcap      Well-behaved capture: two distinct clients, each with a
                       UNIQUE xid, chaddr == eth_src, and opt61 client-id
                       PRESENT. Normal DISCOVER/OFFER/REQUEST/ACK. Serves as the
                       false-positive guard: detectors must report no HIGH
                       findings here.

  dhcpd.leases         ISC DHCPv4 lease file in the BROKEN state: .171 and .172
                       BOTH bound active to 34:fe:9e:3d:ad:c8 (the unit that
                       stole both), plus a third lease to another MAC. Far-future
                       'ends' so they count active.

  dhcpd6.leases        ISC DHCPv6 lease file exercising DUID-LLT (type 1),
                       DUID-LL (type 3) and DUID-EN (type 2) so that
                       extract_mac_from_duid is testable, each ia-na carrying an
                       active iaaddr. DHCPv6 is the unaffected control: every
                       unit has a unique DUID.

  kea-leases4.csv      Kea v4 CSV: valid header plus an expired row and an active
                       row for the SAME IP (journal-dedup test) and a declined
                       row.

  kea-leases6.csv      Kea v6 CSV: valid header plus active/expired ia-na rows.

Run:  PYTHONPATH=src python tools/make_fixtures.py
"""

import os
import struct

# ---------------------------------------------------------------------------
# Output location: <repo_root>/tests/fixtures.  This file lives in
# <repo_root>/tools/make_fixtures.py, so the repo root is its parent's parent.
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
FIXTURES_DIR = os.path.join(_REPO_ROOT, "tests", "fixtures")

# ---------------------------------------------------------------------------
# FIXED time bases (no wall-clock).  BASE_EPOCH is chosen to correspond to the
# wall-clock instant 13:45:03 of the bug-report capture so that adding the
# documented second offsets reproduces 13:45:03.843 .. 13:45:09.387.  The exact
# real-world calendar mapping is irrelevant -- determinism is what matters.
# ---------------------------------------------------------------------------
BASE_EPOCH = 1774964703           # integer seconds; == report "13:45:03"
CLEAN_EPOCH = 1774970000          # distinct fixed base for the clean capture
# Far-future lease 'ends' (year 2099) so ISC leases count as active forever.
ISC_ENDS = "2099/12/31 23:59:59"
ISC_STARTS = "2026/06/01 13:45:03"
# Kea expire epochs (fixed integers): one far future (active) one far past.
KEA_EXPIRE_FUTURE = 4102444800    # 2100-01-01 00:00:00 UTC
KEA_EXPIRE_PAST = 1500000000      # 2017-07-14 (expired)

# ---------------------------------------------------------------------------
# Unit / network constants from the bug report.
# ---------------------------------------------------------------------------
SERVER_MAC = "02:00:5e:00:00:01"      # synthetic L2 addr for the DHCP server
SERVER_IP = "192.168.36.1"
BROADCAST_IP = "255.255.255.255"
ZERO_IP = "0.0.0.0"
SUBNET_MASK = "255.255.255.0"
VLAN_MPLANE = 201

# unit -> (mac, requested/offered last-octet, vendor-class)
A1_MAC = "34:fe:9e:3d:ad:a8"
A2_MAC = "34:fe:9e:3d:af:5c"
A3_MAC = "34:fe:9e:3d:ad:c8"
A1_VC = "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600363"
A2_VC = "o-ran-ru2/FJ/44R14-N77a/A1770000213"
A3_VC = "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222"

# DHCP message type codes (RFC 2131 / opt53).
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)

# Ethertypes.
ETH_8021Q = 0x8100
ETH_IPV4 = 0x0800


# ---------------------------------------------------------------------------
# Low-level encoders (pure struct / bytes).
# ---------------------------------------------------------------------------
def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def ipv4_checksum(data: bytes) -> int:
    """One's-complement 16-bit checksum over an IPv4 header."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_dhcp_options(opts) -> bytes:
    """opts is an iterable of (code:int, value:bytes); appends 0xFF terminator."""
    out = bytearray()
    for code, value in opts:
        out.append(code)
        out.append(len(value))
        out += value
    out.append(0xFF)  # End option
    return bytes(out)


def build_bootp(op, xid, ciaddr, yiaddr, siaddr, giaddr, chaddr_mac, options) -> bytes:
    """
    Build a BOOTP/DHCP message body (fixed header + magic cookie + options).
      op: 1=BOOTREQUEST (client), 2=BOOTREPLY (server)
    """
    htype = 1          # Ethernet
    hlen = 6
    hops = 0
    secs = 0
    flags = 0x8000     # broadcast flag set (O-RUs request broadcast replies)
    chaddr = mac_to_bytes(chaddr_mac) + b"\x00" * (16 - 6)
    sname = b"\x00" * 64
    file_ = b"\x00" * 128
    magic = b"\x63\x82\x53\x63"   # DHCP magic cookie

    body = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        op, htype, hlen, hops,
        xid, secs, flags,
        ip_to_bytes(ciaddr), ip_to_bytes(yiaddr),
        ip_to_bytes(siaddr), ip_to_bytes(giaddr),
        chaddr, sname, file_,
    )
    return body + magic + build_dhcp_options(options)


def build_udp(src_ip, dst_ip, src_port, dst_port, payload) -> bytes:
    """UDP datagram with a valid IPv4 pseudo-header checksum."""
    length = 8 + len(payload)
    header_no_csum = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = ip_to_bytes(src_ip) + ip_to_bytes(dst_ip) + struct.pack("!BBH", 0, 17, length)
    csum = ipv4_checksum(pseudo + header_no_csum + payload)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + payload


def build_ipv4(src_ip, dst_ip, payload, ident=0x0000) -> bytes:
    """IPv4 header (proto 17 UDP) + payload, with header checksum."""
    version_ihl = 0x45
    tos = 0x10                     # IPPREC routine / low-delay (cosmetic)
    total_len = 20 + len(payload)
    flags_frag = 0x0000
    ttl = 64
    proto = 17                     # UDP
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ident, flags_frag, ttl, proto, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    csum = ipv4_checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ident, flags_frag, ttl, proto, csum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    return header + payload


def build_eth_vlan(eth_src, eth_dst, vlan, inner_ethertype, l3_payload) -> bytes:
    """Ethernet II frame with a single 802.1Q tag."""
    dst = mac_to_bytes(eth_dst)
    src = mac_to_bytes(eth_src)
    # 802.1Q: TPID 0x8100, then PCP(3)/DEI(1)/VID(12) + inner ethertype.
    tci = (0 << 13) | (0 << 12) | (vlan & 0x0FFF)
    tag = struct.pack("!HH", ETH_8021Q, tci) + struct.pack("!H", inner_ethertype)
    return dst + src + tag + l3_payload


def build_frame(eth_src, eth_dst, vlan, src_ip, dst_ip, src_port, dst_port,
                bootp_body, ident=0x0000) -> bytes:
    """Full Ethernet(802.1Q)/IPv4/UDP/BOOTP frame as raw on-the-wire bytes."""
    udp = build_udp(src_ip, dst_ip, src_port, dst_port, bootp_body)
    ipv4 = build_ipv4(src_ip, dst_ip, udp, ident=ident)
    return build_eth_vlan(eth_src, eth_dst, vlan, ETH_IPV4, ipv4)


# ---------------------------------------------------------------------------
# pcap container (classic, little-endian, microsecond resolution, linktype 1).
# ---------------------------------------------------------------------------
PCAP_MAGIC_USEC_LE = 0xA1B2C3D4
LINKTYPE_EN10MB = 1


def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC_USEC_LE,  # magic number
        2, 4,                # version major/minor
        0,                   # thiszone (GMT)
        0,                   # sigfigs
        65535,               # snaplen
        LINKTYPE_EN10MB,     # network (EN10MB)
    )


def pcap_record(ts_sec: int, ts_usec: int, frame: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


def write_pcap(path: str, records) -> int:
    """records: iterable of (ts_sec, ts_usec, frame_bytes). Returns byte count."""
    blob = bytearray(pcap_global_header())
    for ts_sec, ts_usec, frame in records:
        blob += pcap_record(ts_sec, ts_usec, frame)
    with open(path, "wb") as fh:
        fh.write(blob)
    return len(blob)


# ---------------------------------------------------------------------------
# DHCP option builders (typed helpers).
# ---------------------------------------------------------------------------
def opt_msg_type(t):
    return (53, bytes([t]))


def opt_server_id(ip):
    return (54, ip_to_bytes(ip))


def opt_requested_ip(ip):
    return (50, ip_to_bytes(ip))


def opt_vendor_class(s):
    return (60, s.encode("ascii"))


def opt_client_id(mac):
    # RFC 2132 type 0x01 (Ethernet) + 6-byte hardware address.
    return (61, b"\x01" + mac_to_bytes(mac))


def opt_subnet_mask(mask):
    return (1, ip_to_bytes(mask))


def opt_lease_time(secs):
    return (51, struct.pack("!I", secs))


# ---------------------------------------------------------------------------
# Fixture 1: oru_xid_reuse.pcap  (the BUG)
# ---------------------------------------------------------------------------
def ip_in_subnet(last_octet):
    return "192.168.36.%d" % last_octet


def make_oru_xid_reuse():
    """Reproduce the two shared-xid sequences from the bug report."""
    XID1 = 0x8FC37A94
    XID2 = 0xCB07F611
    recs = []

    def client_pkt(off_sec, off_usec, src_mac, msg_type, xid, extra_opts):
        opts = [opt_msg_type(msg_type)] + list(extra_opts) + [opt_vendor_class_for(src_mac)]
        body = build_bootp(
            op=1, xid=xid, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
            siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr_mac=src_mac, options=opts,
        )
        frame = build_frame(
            eth_src=src_mac, eth_dst="ff:ff:ff:ff:ff:ff", vlan=VLAN_MPLANE,
            src_ip=ZERO_IP, dst_ip=BROADCAST_IP, src_port=68, dst_port=67,
            bootp_body=body, ident=(xid & 0xFFFF),
        )
        recs.append((BASE_EPOCH + off_sec, off_usec, frame))

    def server_pkt(off_sec, off_usec, dst_chaddr_mac, msg_type, xid, yiaddr,
                   extra_opts):
        opts = [opt_msg_type(msg_type), opt_server_id(SERVER_IP)] + list(extra_opts)
        body = build_bootp(
            op=2, xid=xid, ciaddr=ZERO_IP, yiaddr=yiaddr,
            siaddr=SERVER_IP, giaddr=ZERO_IP, chaddr_mac=dst_chaddr_mac,
            options=opts,
        )
        frame = build_frame(
            eth_src=SERVER_MAC, eth_dst="ff:ff:ff:ff:ff:ff", vlan=VLAN_MPLANE,
            src_ip=SERVER_IP, dst_ip=BROADCAST_IP, src_port=67, dst_port=68,
            bootp_body=body, ident=(xid & 0xFFFF),
        )
        recs.append((BASE_EPOCH + off_sec, off_usec, frame))

    def opt_vendor_class_for(mac):
        return {
            A1_MAC: opt_vendor_class(A1_VC),
            A2_MAC: opt_vendor_class(A2_VC),
            A3_MAC: opt_vendor_class(A3_VC),
        }[mac]

    # ---- Sequence #1: xid 0x8fc37a94, subnet 192.168.36.0/24, server .1 ----
    # 13:45:03.843  ad:c8 DISCOVER
    client_pkt(0, 843000, A3_MAC, DISCOVER, XID1,
               [])
    # 13:45:04.844  server OFFER .171 to ad:c8
    server_pkt(1, 844000, A3_MAC, OFFER, XID1, ip_in_subnet(171),
               [opt_subnet_mask(SUBNET_MASK), opt_lease_time(86400)])
    # 13:45:04.966  ad:c8 REQUEST .171 -> ACK  (ad:c8 legitimately gets .171)
    client_pkt(1, 966000, A3_MAC, REQUEST, XID1,
               [opt_requested_ip(ip_in_subnet(171)), opt_server_id(SERVER_IP)])
    server_pkt(1, 970000, A3_MAC, ACK, XID1, ip_in_subnet(171),
               [opt_subnet_mask(SUBNET_MASK), opt_lease_time(86400)])
    # 13:45:04.990  af:5c REQUEST .171 -> NAK  (af:5c tried to steal .171)
    client_pkt(1, 990000, A2_MAC, REQUEST, XID1,
               [opt_requested_ip(ip_in_subnet(171)), opt_server_id(SERVER_IP)])
    server_pkt(1, 994000, A2_MAC, NAK, XID1, ZERO_IP, [])

    # ---- Sequence #2: xid 0xcb07f611 ----
    # 13:45:08.244  ad:a8 DISCOVER
    client_pkt(5, 244000, A1_MAC, DISCOVER, XID2, [])
    # 13:45:09.245  server OFFER .172 to ad:a8
    server_pkt(6, 245000, A1_MAC, OFFER, XID2, ip_in_subnet(172),
               [opt_subnet_mask(SUBNET_MASK), opt_lease_time(86400)])
    # 13:45:09.336  ad:c8 REQUEST .172 -> ACK  (ad:c8 STEALS .172)
    client_pkt(6, 336000, A3_MAC, REQUEST, XID2,
               [opt_requested_ip(ip_in_subnet(172)), opt_server_id(SERVER_IP)])
    server_pkt(6, 340000, A3_MAC, ACK, XID2, ip_in_subnet(172),
               [opt_subnet_mask(SUBNET_MASK), opt_lease_time(86400)])
    # 13:45:09.370  ad:a8 REQUEST .172 -> NAK  (legit owner rejected)
    client_pkt(6, 370000, A1_MAC, REQUEST, XID2,
               [opt_requested_ip(ip_in_subnet(172)), opt_server_id(SERVER_IP)])
    server_pkt(6, 374000, A1_MAC, NAK, XID2, ZERO_IP, [])
    # 13:45:09.387  af:5c REQUEST .172 -> NAK
    client_pkt(6, 387000, A2_MAC, REQUEST, XID2,
               [opt_requested_ip(ip_in_subnet(172)), opt_server_id(SERVER_IP)])
    server_pkt(6, 391000, A2_MAC, NAK, XID2, ZERO_IP, [])

    return write_pcap(os.path.join(FIXTURES_DIR, "oru_xid_reuse.pcap"), recs)


# ---------------------------------------------------------------------------
# Fixture 2: clean_dhcp.pcap  (false-positive guard)
# ---------------------------------------------------------------------------
def make_clean_dhcp():
    """Two well-behaved clients: unique xid, chaddr==eth_src, opt61 present."""
    recs = []
    C1_MAC = "aa:bb:cc:00:00:11"
    C2_MAC = "aa:bb:cc:00:00:22"
    C1_XID = 0x11223344
    C2_XID = 0x55667788
    C1_IP = "10.0.0.51"
    C2_IP = "10.0.0.52"
    SRV_IP = "10.0.0.1"
    MASK = "255.255.255.0"

    def client_pkt(off_sec, off_usec, mac, msg_type, xid, vc, extra):
        opts = [opt_msg_type(msg_type)] + list(extra) + [
            opt_client_id(mac),                  # opt61 PRESENT -> clean
            opt_vendor_class(vc),
        ]
        body = build_bootp(
            op=1, xid=xid, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
            siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr_mac=mac, options=opts,
        )
        frame = build_frame(
            eth_src=mac, eth_dst="ff:ff:ff:ff:ff:ff", vlan=VLAN_MPLANE,
            src_ip=ZERO_IP, dst_ip=BROADCAST_IP, src_port=68, dst_port=67,
            bootp_body=body, ident=(xid & 0xFFFF),
        )
        recs.append((CLEAN_EPOCH + off_sec, off_usec, frame))

    def server_pkt(off_sec, off_usec, mac, msg_type, xid, yiaddr):
        opts = [opt_msg_type(msg_type), opt_server_id(SRV_IP),
                opt_subnet_mask(MASK), opt_lease_time(86400)]
        body = build_bootp(
            op=2, xid=xid, ciaddr=ZERO_IP, yiaddr=yiaddr,
            siaddr=SRV_IP, giaddr=ZERO_IP, chaddr_mac=mac, options=opts,
        )
        frame = build_frame(
            eth_src=SERVER_MAC, eth_dst="ff:ff:ff:ff:ff:ff", vlan=VLAN_MPLANE,
            src_ip=SRV_IP, dst_ip=BROADCAST_IP, src_port=67, dst_port=68,
            bootp_body=body, ident=(xid & 0xFFFF),
        )
        recs.append((CLEAN_EPOCH + off_sec, off_usec, frame))

    # Client 1 full handshake.
    client_pkt(0, 100000, C1_MAC, DISCOVER, C1_XID, "generic-client/1.0", [])
    server_pkt(0, 200000, C1_MAC, OFFER, C1_XID, C1_IP)
    client_pkt(0, 300000, C1_MAC, REQUEST, C1_XID, "generic-client/1.0",
               [opt_requested_ip(C1_IP), opt_server_id(SRV_IP)])
    server_pkt(0, 400000, C1_MAC, ACK, C1_XID, C1_IP)

    # Client 2 full handshake, distinct xid.
    client_pkt(1, 100000, C2_MAC, DISCOVER, C2_XID, "generic-client/1.0", [])
    server_pkt(1, 200000, C2_MAC, OFFER, C2_XID, C2_IP)
    client_pkt(1, 300000, C2_MAC, REQUEST, C2_XID, "generic-client/1.0",
               [opt_requested_ip(C2_IP), opt_server_id(SRV_IP)])
    server_pkt(1, 400000, C2_MAC, ACK, C2_XID, C2_IP)

    return write_pcap(os.path.join(FIXTURES_DIR, "clean_dhcp.pcap"), recs)


# ---------------------------------------------------------------------------
# Fixture 3: dhcpd.leases  (ISC v4, broken state)
# ---------------------------------------------------------------------------
def make_dhcpd_leases():
    """
    .171 and .172 BOTH active to 34:fe:9e:3d:ad:c8 (the thief, duplicate grant),
    plus a third lease to another MAC. Far-future 'ends' so all count active.
    """
    text = """\
# ISC dhcpd.leases -- BROKEN state captured during the O-RU xid-reuse incident.
# Unit 34:fe:9e:3d:ad:c8 holds TWO active leases (.171 and .172) -- the symptom
# of the shared-xid IP-theft defect. A third, healthy lease is included so the
# conflict detector can distinguish the duplicate from normal leases.

lease 192.168.36.171 {
  starts 4 %(starts)s;
  ends 5 %(ends)s;
  cltt 4 %(starts)s;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 34:fe:9e:3d:ad:c8;
  client-hostname "oru-adc8";
  set vendor-class-identifier = "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222";
  option vendor-class-identifier "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222";
}
lease 192.168.36.172 {
  starts 4 %(starts)s;
  ends 5 %(ends)s;
  cltt 4 %(starts)s;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 34:fe:9e:3d:ad:c8;
  client-hostname "oru-adc8";
  option vendor-class-identifier "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222";
}
lease 192.168.36.170 {
  starts 4 %(starts)s;
  ends 5 %(ends)s;
  cltt 4 %(starts)s;
  binding state active;
  next binding state free;
  hardware ethernet 34:fe:9e:3d:ad:a8;
  client-hostname "oru-ada8";
  option vendor-class-identifier "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600363";
}
lease 192.168.36.160 {
  starts 4 %(starts)s;
  ends 5 2020/01/01 00:00:00;
  cltt 4 %(starts)s;
  binding state free;
  hardware ethernet 34:fe:9e:3d:af:5c;
}
""" % {"starts": ISC_STARTS, "ends": ISC_ENDS}
    path = os.path.join(FIXTURES_DIR, "dhcpd.leases")
    data = text.encode("ascii")
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# Fixture 4: dhcpd6.leases  (ISC v6, DUID-LLT / DUID-LL / DUID-EN)
# ---------------------------------------------------------------------------
def _escape_for_isc_key(raw: bytes) -> str:
    """
    Render a byte string the way ISC dhcpd writes binary ia-na keys: printable
    ASCII verbatim, everything else as an octal \\NNN escape. This is exactly
    the inverse of the leases parser's
        raw_unicode_escape -> unicode_escape -> latin-1
    round-trip, so extract_mac_from_duid recovers the original bytes.
    """
    out = []
    for b in raw:
        if b == 0x5C:                      # backslash
            out.append("\\\\")
        elif b == 0x22:                    # double quote
            out.append("\\\"")
        elif 0x20 <= b < 0x7F:             # printable ASCII
            out.append(chr(b))
        else:
            out.append("\\%03o" % b)       # octal escape, ISC style
    return "".join(out)


def _duid_llt(hwtype: int, time_val: int, mac: str) -> bytes:
    # DUID-LLT: type(2)=1, hwtype(2), time(4), link-layer addr(6).
    return struct.pack("!HHI", 1, hwtype, time_val) + mac_to_bytes(mac)


def _duid_ll(hwtype: int, mac: str) -> bytes:
    # DUID-LL: type(2)=3, hwtype(2), link-layer addr(6).
    return struct.pack("!HH", 3, hwtype) + mac_to_bytes(mac)


def _duid_en(enterprise: int, identifier: bytes) -> bytes:
    # DUID-EN: type(2)=2, enterprise-number(4), identifier(var).
    return struct.pack("!HI", 2, enterprise) + identifier


def make_dhcpd6_leases():
    """
    Three ia-na blocks, one per DUID flavour. The leases parser prepends a
    4-byte IAID to the DUID inside the ia-na key, so we emit IAID||DUID and let
    extract_mac_from_duid strip the IAID back off.
    """
    iaid = b"\x00\x01\x00\x01"             # 4-byte IAID prefix (key layout)

    # DUID-LLT (type 1) for unit A1.
    llt = _duid_llt(1, 0x29A4F300, A1_MAC)
    key_llt = _escape_for_isc_key(iaid + llt)

    # DUID-LL (type 3) for unit A3.
    ll = _duid_ll(1, A3_MAC)
    key_ll = _escape_for_isc_key(iaid + ll)

    # DUID-EN (type 2): enterprise 0x00000937, identifier embeds an ASCII MAC.
    en_ascii = A2_MAC.encode("ascii")      # "34:fe:9e:3d:af:5c"
    en = _duid_en(0x00000937, en_ascii)
    key_en = _escape_for_isc_key(iaid + en)

    text = (
        "# ISC dhcpd6.leases -- DHCPv6 is the UNAFFECTED control plane.\n"
        "# Each O-RU has a UNIQUE DUID (no shared transaction-id problem here).\n"
        "# Blocks exercise DUID-LLT (type 1), DUID-LL (type 3), DUID-EN (type 2)\n"
        "# so extract_mac_from_duid is testable for all three encodings.\n"
        "\n"
        "server-duid \"\\000\\001\\000\\001\\051\\244\\363\\000\\002\\000\\136\\000\\000\\001\";\n"
        "\n"
        'ia-na "%s" {\n'
        "  cltt 4 %s;\n"
        "  iaaddr fd00:36::171 {\n"
        "    binding state active;\n"
        "    preferred-life 3600;\n"
        "    max-life 7200;\n"
        "    ends 5 %s;\n"
        "  }\n"
        "}\n"
        'ia-na "%s" {\n'
        "  cltt 4 %s;\n"
        "  iaaddr fd00:36::172 {\n"
        "    binding state active;\n"
        "    preferred-life 3600;\n"
        "    max-life 7200;\n"
        "    ends 5 %s;\n"
        "  }\n"
        "}\n"
        'ia-na "%s" {\n'
        "  cltt 4 %s;\n"
        "  iaaddr fd00:36::173 {\n"
        "    binding state active;\n"
        "    preferred-life 3600;\n"
        "    max-life 7200;\n"
        "    ends 5 %s;\n"
        "  }\n"
        "}\n"
    ) % (
        key_llt, ISC_STARTS, ISC_ENDS,
        key_ll, ISC_STARTS, ISC_ENDS,
        key_en, ISC_STARTS, ISC_ENDS,
    )

    path = os.path.join(FIXTURES_DIR, "dhcpd6.leases")
    data = text.encode("latin-1")
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# Fixture 5a: kea-leases4.csv
# ---------------------------------------------------------------------------
def make_kea_leases4():
    """
    Kea v4 CSV. Includes an expired row and an active row for the SAME IP
    (.171) to test journal-dedup (active must win), plus a declined row.
    """
    header = ("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"
              "fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id")
    rows = [
        # Same IP twice: an older expired (state 2) row then an active (0) row.
        "192.168.36.171,34:fe:9e:3d:ad:c8,,3600,%d,1,0,0,oru-adc8,2,,0"
        % KEA_EXPIRE_PAST,
        "192.168.36.171,34:fe:9e:3d:ad:c8,,3600,%d,1,0,0,oru-adc8,0,,0"
        % KEA_EXPIRE_FUTURE,
        # Declined address (state 1).
        "192.168.36.180,,,3600,%d,1,0,0,,1,,0" % KEA_EXPIRE_FUTURE,
        # A normal distinct active lease.
        "192.168.36.170,34:fe:9e:3d:ad:a8,,3600,%d,1,0,0,oru-ada8,0,,0"
        % KEA_EXPIRE_FUTURE,
    ]
    text = header + "\n" + "\n".join(rows) + "\n"
    path = os.path.join(FIXTURES_DIR, "kea-leases4.csv")
    data = text.encode("ascii")
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# Fixture 5b: kea-leases6.csv
# ---------------------------------------------------------------------------
def make_kea_leases6():
    """
    Kea v6 CSV. Includes an expired and an active row for the SAME IP
    (journal-dedup), one prefix-delegation (lease_type 2) row that the parser
    must skip, and a declined row.
    """
    header = ("address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,"
              "lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,"
              "state,user_context,hwtype,hwaddr_source,pool_id")
    rows = [
        # Same address: expired then active (active must win).
        "fd00:36::171,00:01:00:01:29:a4:f3:00:34:fe:9e:3d:ad:a8,3600,%d,1,1800,"
        "0,1,128,0,0,oru-ada8,34:fe:9e:3d:ad:a8,2,,1,0,0" % KEA_EXPIRE_PAST,
        "fd00:36::171,00:01:00:01:29:a4:f3:00:34:fe:9e:3d:ad:a8,3600,%d,1,1800,"
        "0,1,128,0,0,oru-ada8,34:fe:9e:3d:ad:a8,0,,1,0,0" % KEA_EXPIRE_FUTURE,
        # Prefix delegation (lease_type 2) -- parser skips this.
        "fd00:36:abcd::,00:03:00:01:34:fe:9e:3d:ad:c8,3600,%d,1,1800,"
        "2,2,64,0,0,,34:fe:9e:3d:ad:c8,0,,1,0,0" % KEA_EXPIRE_FUTURE,
        # Declined (state 1) ia-na address.
        "fd00:36::180,00:03:00:01:34:fe:9e:3d:af:5c,3600,%d,1,1800,"
        "0,3,128,0,0,,34:fe:9e:3d:af:5c,1,,1,0,0" % KEA_EXPIRE_FUTURE,
    ]
    text = header + "\n" + "\n".join(rows) + "\n"
    path = os.path.join(FIXTURES_DIR, "kea-leases6.csv")
    data = text.encode("ascii")
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------
def main():
    os.makedirs(FIXTURES_DIR, exist_ok=True)

    builders = [
        ("oru_xid_reuse.pcap", make_oru_xid_reuse),
        ("clean_dhcp.pcap", make_clean_dhcp),
        ("dhcpd.leases", make_dhcpd_leases),
        ("dhcpd6.leases", make_dhcpd6_leases),
        ("kea-leases4.csv", make_kea_leases4),
        ("kea-leases6.csv", make_kea_leases6),
    ]

    print("Writing deterministic fixtures to %s" % FIXTURES_DIR)
    for name, fn in builders:
        nbytes = fn()
        print("  wrote %-22s %6d bytes" % (name, nbytes))
    print("Done: %d fixtures." % len(builders))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
