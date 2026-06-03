"""
Tests for dhcp_toolkit.forensics.dhcp.decode_dhcpv4 / decode_dhcpv6.

  * decode_dhcpv4 on a known buggy frame returns correct
    xid / chaddr / msg_type / requested_ip, and client_id is None (NO opt61).
  * decode_dhcpv4 on a clean_dhcp.pcap frame returns a non-None client_id
    (opt61 present).
  * decode_dhcpv6 on the real capture's SOLICIT decodes a client DUID.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path, real_pcap_path

from dhcp_toolkit.forensics.pcap import read_pcap
from dhcp_toolkit.forensics.dhcp import (
    decode_dhcpv4,
    decode_dhcpv6,
    DHCPV4_TYPES,
    DHCPV6_TYPES,
)
from dhcp_toolkit.forensics.models import DHCPv4Message, DHCPv6Message


def _decoded_v4(pcap_path):
    """Decode every DHCPv4 frame in a pcap -> list[DHCPv4Message]."""
    out = []
    for p in read_pcap(pcap_path):
        if p.l4 == "udp" and (p.src_port in (67, 68) or p.dst_port in (67, 68)):
            msg = decode_dhcpv4(p.payload)
            if msg is not None:
                out.append(msg)
    return out


# --------------------------------------------------------------------------
# Type tables
# --------------------------------------------------------------------------

def test_dhcp_type_tables_present():
    # Core message types must be mapped.
    assert DHCPV4_TYPES.get(1) and "DISCOVER" in DHCPV4_TYPES[1].upper()
    assert DHCPV4_TYPES.get(2) and "OFFER" in DHCPV4_TYPES[2].upper()
    assert DHCPV4_TYPES.get(3) and "REQUEST" in DHCPV4_TYPES[3].upper()
    assert DHCPV4_TYPES.get(5) and "ACK" in DHCPV4_TYPES[5].upper()
    assert DHCPV4_TYPES.get(6) and "NAK" in DHCPV4_TYPES[6].upper()
    # DHCPv6 SOLICIT == 1.
    assert DHCPV6_TYPES.get(1) and "SOLICIT" in DHCPV6_TYPES[1].upper()


# --------------------------------------------------------------------------
# Buggy capture: known frame fields + missing opt61
# --------------------------------------------------------------------------

def test_decode_dhcpv4_known_discover_frame():
    ensure_fixtures()
    msgs = _decoded_v4(fixture_path("oru_xid_reuse.pcap"))
    assert msgs, "no DHCPv4 messages decoded from oru_xid_reuse.pcap"
    # Find the DISCOVER from ad:c8 carrying the reused xid 0x8fc37a94.
    discovers = [
        m for m in msgs
        if m.msg_type == 1
        and m.xid == _helpers.XID_SEQ1
        and m.chaddr == _helpers.MAC_A3_ADC8
    ]
    assert discovers, "expected a DISCOVER xid=0x8fc37a94 chaddr=ad:c8"
    m = discovers[0]
    assert isinstance(m, DHCPv4Message)
    assert m.xid == _helpers.XID_SEQ1
    assert m.chaddr == _helpers.MAC_A3_ADC8
    assert "DISCOVER" in m.msg_type_name.upper()
    # DEFECT (3): no DHCPv4 option 61 client-id present.
    assert m.client_id is None, "buggy O-RU frame must lack opt61 client-id"
    # opt60 vendor-class is present and O-RAN-flavoured.
    assert m.vendor_class is not None
    assert _helpers.VENDOR_PREFIX in m.vendor_class


def test_decode_dhcpv4_known_request_has_requested_ip():
    ensure_fixtures()
    msgs = _decoded_v4(fixture_path("oru_xid_reuse.pcap"))
    # The REQUEST for .171 (option 50 requested-ip) -- regardless of which unit
    # sent it, the requested_ip option must decode to 192.168.36.171.
    reqs = [
        m for m in msgs
        if m.msg_type == 3 and m.requested_ip == _helpers.IP_171
    ]
    assert reqs, "expected a REQUEST with requested_ip 192.168.36.171"
    for m in reqs:
        assert m.client_id is None  # still no opt61 on the buggy units


def test_decode_dhcpv4_all_buggy_frames_lack_client_id():
    ensure_fixtures()
    msgs = _decoded_v4(fixture_path("oru_xid_reuse.pcap"))
    assert msgs
    # Every DHCPv4 message in the buggy capture lacks opt61.
    assert all(m.client_id is None for m in msgs)


def test_decode_dhcpv4_bad_payload_returns_none():
    # Not a BOOTP/DHCP payload -> None, never raise.
    assert decode_dhcpv4(b"") is None
    assert decode_dhcpv4(b"\x00\x01\x02") is None


# --------------------------------------------------------------------------
# Clean capture: opt61 present
# --------------------------------------------------------------------------

def test_decode_dhcpv4_clean_has_client_id():
    ensure_fixtures()
    msgs = _decoded_v4(fixture_path("clean_dhcp.pcap"))
    assert msgs, "no DHCPv4 messages decoded from clean_dhcp.pcap"
    # The fixed/clean units include option 61, so at least the client-originated
    # frames carry a non-None client_id.
    client_frames = [m for m in msgs if m.op == 1]  # BOOTREQUEST
    assert client_frames, "expected client-originated frames in clean_dhcp.pcap"
    assert any(m.client_id is not None for m in client_frames), \
        "clean capture must include opt61 client-id"


# --------------------------------------------------------------------------
# DHCPv6 decode on the real capture
# --------------------------------------------------------------------------

def test_decode_dhcpv6_real_client_message():
    packets = read_pcap(real_pcap_path())
    v6 = [
        p for p in packets
        if p.l4 == "udp" and (p.src_port in (546, 547) or p.dst_port in (546, 547))
    ]
    assert v6, "expected a DHCPv6 frame in the real capture"
    decoded = [decode_dhcpv6(p.payload) for p in v6]
    decoded = [m for m in decoded if m is not None]
    assert decoded, "DHCPv6 client message did not decode"
    m = decoded[0]
    assert isinstance(m, DHCPv6Message)
    # The genuine capture carries a single client-originated DHCPv6 exchange
    # (SOLICIT/REQUEST/RENEW family); the exact type is whatever the real O-RU
    # emitted -- it must be a recognised client type, not a server reply.
    assert m.msg_type in DHCPV6_TYPES, "unknown DHCPv6 msg_type %r" % (m.msg_type,)
    # SOLICIT(1) REQUEST(3) CONFIRM(4) RENEW(5) REBIND(6) RELEASE(8) DECLINE(9)
    # INFORMATION-REQUEST(11) are all client-originated.
    assert m.msg_type in (1, 3, 4, 5, 6, 8, 9, 11), \
        "expected a client-originated DHCPv6 message, got %s (%s)" % (
            m.msg_type, m.msg_type_name,
        )
    # DHCPv6 is unaffected because each unit has a UNIQUE DUID; the client
    # message carries a client DUID, and that DUID embeds the unit's MAC/serial.
    assert m.client_duid is not None
    # The unaffected control plane is the O-RAN fronthaul: when a vendor-class
    # is exposed it should identify a Fujitsu O-RU.  Implementations may surface
    # this either as decoded ASCII or as the raw hex of the option payload, so
    # accept the O-RAN identity in either representation.
    if m.vendor_class is not None:
        vc = m.vendor_class.lower()
        ascii_hint = "fj" in vc or "o-ran" in vc
        # "o-ran-ru2/FJ" encoded as ASCII-in-hex.
        hex_hint = _helpers.VENDOR_PREFIX.encode("ascii").hex() in vc
        assert ascii_hint or hex_hint, \
            "DHCPv6 vendor_class does not identify an O-RAN/Fujitsu O-RU: %r" % (
                m.vendor_class,
            )
