"""
Tests for dhcp_toolkit.leases.conflicts.find_conflicts.

The broken ISC v4 lease fixture encodes the report's failure mode: the thieving
unit ad:c8 actively holds BOTH .171 and .172.  find_conflicts must flag this as
a 'mac_multiple_active_ips' conflict at HIGH severity.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path

from dhcp_toolkit.leases.parsers import parse_isc_v4
from dhcp_toolkit.leases.conflicts import find_conflicts
from dhcp_toolkit.leases.models import Conflict, Lease


def _load_broken_v4():
    ensure_fixtures()
    return parse_isc_v4(fixture_path("dhcpd.leases"))


def test_find_conflicts_returns_conflict_objects():
    leases = _load_broken_v4()
    conflicts = find_conflicts(leases)
    assert isinstance(conflicts, list)
    assert all(isinstance(c, Conflict) for c in conflicts)


def test_find_conflicts_flags_mac_multiple_active_ips_high():
    leases = _load_broken_v4()
    conflicts = find_conflicts(leases)
    hits = [c for c in conflicts if c.kind == "mac_multiple_active_ips"]
    assert hits, "expected a mac_multiple_active_ips conflict for ad:c8"
    # The offending unit is ad:c8, and it holds both contested addresses.
    target = None
    for c in hits:
        if _helpers.MAC_A3_ADC8 in c.macs:
            target = c
            break
    assert target is not None, "ad:c8 not named in any mac_multiple_active_ips conflict"
    assert target.severity == "HIGH"
    assert _helpers.IP_171 in target.ips
    assert _helpers.IP_172 in target.ips
    # Detail text should be non-empty and mention the MAC.
    assert target.detail
    assert _helpers.MAC_A3_ADC8 in target.detail


def test_find_conflicts_clean_leases_no_high():
    # A clean lease set (one IP per MAC, one MAC per IP) yields no HIGH conflicts.
    clean = [
        Lease(ip="192.168.36.10", version="4", server="isc", state="active",
              mac="34:fe:9e:3d:ad:a8"),
        Lease(ip="192.168.36.11", version="4", server="isc", state="active",
              mac="34:fe:9e:3d:af:5c"),
        Lease(ip="192.168.36.12", version="4", server="isc", state="active",
              mac="34:fe:9e:3d:ad:c8"),
    ]
    conflicts = find_conflicts(clean)
    assert all(c.severity != "HIGH" for c in conflicts), \
        "clean lease set must not produce HIGH conflicts"
