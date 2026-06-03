"""Pure-stdlib decoders for DHCPv4 (BOOTP) and DHCPv6 message payloads.

DHCPv4 follows RFC 2131 (message format) and RFC 2132 (options). The fixed
BOOTP header is 236 bytes, followed by the 4-byte magic cookie 63:82:53:63
(RFC 1497 / 951) and then a TLV option stream terminated by option 255.

DHCPv6 follows RFC 8415: a 1-byte message type, a 3-byte transaction-id, then
a sequence of (option-code:2, option-len:2, value) TLVs. Option 3 (IA_NA)
nests IAADDR (option 5) sub-options that carry the leased address.

These decoders are defensive: any structurally invalid payload yields ``None``
rather than an exception, and individual malformed options are skipped.
"""

import struct
from typing import Optional

from .models import DHCPv4Message, DHCPv6Message

# RFC 2132 option 53 message types.
DHCPV4_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

# RFC 8415 message types.
DHCPV6_TYPES = {
    1: "SOLICIT",
    2: "ADVERTISE",
    3: "REQUEST",
    4: "CONFIRM",
    5: "RENEW",
    6: "REBIND",
    7: "REPLY",
    8: "RELEASE",
    9: "DECLINE",
    11: "INFORMATION-REQUEST",
    12: "RELAY-FORW",
    13: "RELAY-REPL",
}

# BOOTP magic cookie (RFC 1497) sits at fixed offset 236.
_MAGIC_COOKIE = b"\x63\x82\x53\x63"
_DHCPV4_MIN_LEN = 240  # 236-byte header + 4-byte cookie

# DHCPv4 option codes we extract by name.
_OPT_REQUESTED_IP = 50
_OPT_MSG_TYPE = 53
_OPT_SERVER_ID = 54
_OPT_CLIENT_ID = 61
_OPT_VENDOR_CLASS = 60
_OPT_HOSTNAME = 12
_OPT_END = 255
_OPT_PAD = 0


def _ipv4(b: bytes) -> str:
    """Format 4 raw bytes as dotted-quad."""
    return ".".join(str(x) for x in b[:4])


def decode_dhcpv4(payload: bytes) -> Optional[DHCPv4Message]:
    """Decode a BOOTP/DHCPv4 *payload*; return ``None`` if it is not DHCP.

    Requires at least 240 bytes and the magic cookie 63:82:53:63 at offset
    236. Parses the fixed header, chaddr (``hlen`` bytes from offset 28) and
    the well-known options (53/50/54/61/60/12); all parsed options are also
    stored raw in ``.options`` keyed by option code.
    """
    if payload is None or len(payload) < _DHCPV4_MIN_LEN:
        return None
    if payload[236:240] != _MAGIC_COOKIE:
        return None

    try:
        op = payload[0]
        hlen = payload[2]
        xid = struct.unpack(">I", payload[4:8])[0]
        ciaddr = _ipv4(payload[12:16])
        yiaddr = _ipv4(payload[16:20])
        siaddr = _ipv4(payload[20:24])
        giaddr = _ipv4(payload[24:28])
        # chaddr field is 16 bytes at offset 28; hlen selects the real length.
        if hlen == 0 or hlen > 16:
            hlen = 6
        chaddr_raw = payload[28:28 + hlen]
        chaddr = ":".join("%02x" % x for x in chaddr_raw)
    except (struct.error, IndexError):
        return None

    options: dict = {}
    msg_type: Optional[int] = None
    requested_ip: Optional[str] = None
    server_id: Optional[str] = None
    client_id: Optional[bytes] = None
    client_id_str: Optional[str] = None
    vendor_class: Optional[str] = None
    hostname: Optional[str] = None

    i = _DHCPV4_MIN_LEN
    n = len(payload)
    while i < n:
        code = payload[i]
        if code == _OPT_END:
            break
        if code == _OPT_PAD:
            i += 1
            continue
        # Need a length byte.
        if i + 1 >= n:
            break
        length = payload[i + 1]
        val_start = i + 2
        val_end = val_start + length
        if val_end > n:
            break
        value = payload[val_start:val_end]
        options[code] = value

        if code == _OPT_MSG_TYPE and length >= 1:
            msg_type = value[0]
        elif code == _OPT_REQUESTED_IP and length >= 4:
            requested_ip = _ipv4(value[:4])
        elif code == _OPT_SERVER_ID and length >= 4:
            server_id = _ipv4(value[:4])
        elif code == _OPT_CLIENT_ID:
            client_id = bytes(value)
            client_id_str = client_id.hex()
        elif code == _OPT_VENDOR_CLASS:
            vendor_class = value.decode("latin-1")
        elif code == _OPT_HOSTNAME:
            hostname = value.decode("latin-1")

        i = val_end

    msg_type_name = DHCPV4_TYPES.get(msg_type, "UNKNOWN") if msg_type is not None else "BOOTP"

    return DHCPv4Message(
        op=op, xid=xid, ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr,
        giaddr=giaddr, chaddr=chaddr, msg_type=msg_type, msg_type_name=msg_type_name,
        requested_ip=requested_ip, server_id=server_id, client_id=client_id,
        client_id_str=client_id_str, vendor_class=vendor_class, hostname=hostname,
        options=options,
    )


def _ipv6(b: bytes) -> str:
    """Format 16 raw bytes as a (non-compressed) colon-grouped IPv6 string."""
    return ":".join("%02x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2))


def decode_dhcpv6(payload: bytes) -> Optional[DHCPv6Message]:
    """Decode a DHCPv6 *payload* (RFC 8415); return ``None`` if malformed.

    Reads the 1-byte message type and 3-byte transaction-id, then walks the
    option TLVs: 1=client-id (DUID), 2=server-id, 3=IA_NA (recursing into the
    IAADDR sub-option to recover leased addresses), 16=vendor-class.
    """
    if payload is None or len(payload) < 4:
        return None

    msg_type = payload[0]
    transaction_id = (payload[1] << 16) | (payload[2] << 8) | payload[3]
    msg_type_name = DHCPV6_TYPES.get(msg_type, "UNKNOWN")

    options: dict = {}
    client_duid: Optional[bytes] = None
    server_duid: Optional[bytes] = None
    addresses: list = []
    vendor_class: Optional[str] = None

    i = 4
    n = len(payload)
    while i + 4 <= n:
        try:
            code, length = struct.unpack(">HH", payload[i:i + 4])
        except struct.error:
            return None
        val_start = i + 4
        val_end = val_start + length
        if val_end > n:
            # Truncated option -> the payload is malformed.
            return None
        value = payload[val_start:val_end]
        options[code] = value

        if code == 1:  # OPTION_CLIENTID (DUID)
            client_duid = bytes(value)
        elif code == 2:  # OPTION_SERVERID (DUID)
            server_duid = bytes(value)
        elif code == 3:  # OPTION_IA_NA -> contains IAADDR (option 5) sub-opts
            addresses.extend(_extract_iaaddrs(value))
        elif code == 16:  # OPTION_VENDOR_CLASS
            vendor_class = value.hex()

        i = val_end

    return DHCPv6Message(
        msg_type=msg_type, msg_type_name=msg_type_name, transaction_id=transaction_id,
        client_duid=client_duid, server_duid=server_duid, addresses=addresses,
        vendor_class=vendor_class, options=options,
    )


def _extract_iaaddrs(ia_na: bytes) -> list:
    """Extract IPv6 addresses from an IA_NA option body.

    The IA_NA body is: IAID(4) T1(4) T2(4) then nested options; an IAADDR
    sub-option (code 5) starts with the 16-byte address.
    """
    addrs: list = []
    # Skip the 12-byte IAID/T1/T2 header before the nested options.
    j = 12
    n = len(ia_na)
    while j + 4 <= n:
        try:
            sub_code, sub_len = struct.unpack(">HH", ia_na[j:j + 4])
        except struct.error:
            break
        sub_start = j + 4
        sub_end = sub_start + sub_len
        if sub_end > n:
            break
        if sub_code == 5 and sub_len >= 16:  # OPTION_IAADDR
            addrs.append(_ipv6(ia_na[sub_start:sub_start + 16]))
        j = sub_end
    return addrs
