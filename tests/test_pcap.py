"""
Tests for dhcp_toolkit.forensics.pcap.read_pcap.

  * read_pcap(oru_xid_reuse.pcap) yields the documented DHCP frames, and each
    DHCP frame round-trips with vlan==201, l4=='udp', client/server ports 67/68.
  * read_pcap(samples/oru_real_capture.pcap) does NOT crash and yields packets
    (mostly PTP + a single DHCPv6 SOLICIT, ZERO DHCPv4).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path, real_pcap_path

from dhcp_toolkit.forensics.pcap import read_pcap
from dhcp_toolkit.forensics.models import CapturedPacket


# Per the report, both documented sequences total 9 DHCPv4 frames
# (Seq#1: DISCOVER/OFFER/REQUEST-ACK/REQUEST-NAK = 4; Seq#2: 5).
EXPECTED_MIN_DHCP_FRAMES = 9


def _dhcp_frames(packets):
    """Frames that look like DHCP (UDP on 67/68 v4 or 546/547 v6)."""
    out = []
    for p in packets:
        if p.l4 == "udp" and (
            (p.src_port in (67, 68) or p.dst_port in (67, 68))
            or (p.src_port in (546, 547) or p.dst_port in (546, 547))
        ):
            out.append(p)
    return out


def test_read_pcap_xid_reuse_frame_count():
    ensure_fixtures()
    packets = read_pcap(fixture_path("oru_xid_reuse.pcap"))
    assert isinstance(packets, list)
    assert all(isinstance(p, CapturedPacket) for p in packets)
    dhcp = _dhcp_frames(packets)
    assert len(dhcp) >= EXPECTED_MIN_DHCP_FRAMES, \
        "expected >= %d DHCP frames, got %d" % (EXPECTED_MIN_DHCP_FRAMES, len(dhcp))


def test_read_pcap_xid_reuse_round_trip_fields():
    ensure_fixtures()
    packets = read_pcap(fixture_path("oru_xid_reuse.pcap"))
    dhcp = _dhcp_frames(packets)
    assert dhcp, "no DHCP frames decoded from oru_xid_reuse.pcap"
    for p in dhcp:
        # The O-RAN fronthaul DHCP traffic is tagged on VLAN 201.
        assert p.vlan == 201, "DHCP frame not on VLAN 201: %r" % (p.vlan,)
        assert p.l4 == "udp"
        # DHCPv4 bootp ports.
        ports = {p.src_port, p.dst_port}
        assert ports & {67, 68}, "DHCPv4 frame not on ports 67/68: %r" % (ports,)
        # Indices are assigned in capture order and monotonic.
        assert isinstance(p.index, int)
        # Broadcast destination is expected for the buggy exchange.
        assert p.l3 == "ipv4"


def test_read_pcap_xid_reuse_indices_monotonic():
    ensure_fixtures()
    packets = read_pcap(fixture_path("oru_xid_reuse.pcap"))
    idxs = [p.index for p in packets]
    assert idxs == sorted(idxs)


def test_read_pcap_real_capture_does_not_crash():
    packets = read_pcap(real_pcap_path())
    assert isinstance(packets, list)
    assert len(packets) > 0, "real capture yielded no packets"
    assert all(isinstance(p, CapturedPacket) for p in packets)


def test_read_pcap_real_capture_is_mostly_non_dhcpv4():
    packets = read_pcap(real_pcap_path())
    # The genuine fronthaul capture contains ZERO DHCPv4 frames.
    v4 = [
        p for p in packets
        if p.l4 == "udp" and (p.src_port in (67, 68) or p.dst_port in (67, 68))
    ]
    assert len(v4) == 0, "real capture unexpectedly contains DHCPv4 frames"
    # It is tagged on VLAN 201 and is predominantly non-DHCP (PTP etc.).
    tagged = [p for p in packets if p.vlan == 201]
    assert tagged, "expected VLAN-201 tagged frames in the real capture"
    # There is at least one DHCPv6 frame (the SOLICIT).
    v6 = [
        p for p in packets
        if p.l4 == "udp" and (p.src_port in (546, 547) or p.dst_port in (546, 547))
    ]
    assert len(v6) >= 1, "expected at least one DHCPv6 frame in the real capture"


def test_read_pcap_tolerates_garbage():
    # A truncated / non-pcap file must not crash read_pcap; it returns a list
    # (possibly empty) rather than raising.
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"\x00\x01\x02\x03not a real pcap header at all")
        bad = f.name
    try:
        out = read_pcap(bad)
        assert isinstance(out, list)
    finally:
        os.unlink(bad)
