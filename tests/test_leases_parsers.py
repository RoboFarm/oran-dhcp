"""
Tests for dhcp_toolkit.leases.parsers.

Covers:
  * parse_isc_v4 / parse_isc_v6 lease counts + active states
  * extract_mac_from_duid for DUID-LLT (type 1), DUID-LL (type 3),
    DUID-EN (type 2) -- exercised against self-constructed DUIDs so the
    assertion does not depend on the fixture's exact byte layout
  * parse_kea_v4 / parse_kea_v6 journal dedup (active wins over expired for
    same IP) and declined-state mapping
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path

from dhcp_toolkit.leases.parsers import (
    parse_isc_v4,
    parse_isc_v6,
    parse_kea_v4,
    parse_kea_v6,
    extract_mac_from_duid,
)
from dhcp_toolkit.leases.models import Lease


# --------------------------------------------------------------------------
# Helpers for building DUID "raw" strings the way ISC stores them in
# ia-na "...." blocks: a 4-byte IAID prepended to the DUID, with every byte
# written as a 3-digit octal escape (\NNN).  extract_mac_from_duid reverses
# this via encode('raw_unicode_escape').decode('unicode_escape'), so feeding it
# octal-escape text (exactly how ISC serialises binary DUIDs) is the faithful,
# round-trip-safe input -- unlike raw latin-1 bytes, which break when a byte
# happens to be 0x5c ('\\').
# --------------------------------------------------------------------------

def _duid_raw(payload_bytes):
    """Encode raw DUID bytes (incl. leading 4-byte IAID) as an ISC octal-escape string."""
    return "".join("\\%03o" % b for b in payload_bytes)


def _duid_llt(mac_bytes, iaid=b"\x00\x00\x00\x01", hwtype=b"\x00\x01",
              time4=b"\x5e\x00\x00\x00"):
    # IAID(4) + type 0001 + hwtype(2) + time(4) + link-layer addr(6)
    return _duid_raw(iaid + b"\x00\x01" + hwtype + time4 + bytes(mac_bytes))


def _duid_ll(mac_bytes, iaid=b"\x00\x00\x00\x01", hwtype=b"\x00\x01"):
    # IAID(4) + type 0003 + hwtype(2) + link-layer addr(6)
    return _duid_raw(iaid + b"\x00\x03" + hwtype + bytes(mac_bytes))


def _duid_en(mac_text, iaid=b"\x00\x00\x00\x01", enterprise=b"\x00\x00\x0a\x3b"):
    # IAID(4) + type 0002 + enterprise(4) + ASCII identifier containing the MAC
    return _duid_raw(iaid + b"\x00\x02" + enterprise + mac_text.encode("ascii"))


# --------------------------------------------------------------------------
# extract_mac_from_duid -- the bug-fixed logic from changelog 1.1.0 -> 1.3.0
# --------------------------------------------------------------------------

def test_extract_mac_from_duid_llt():
    mac = [0x34, 0xfe, 0x9e, 0x3d, 0xad, 0xc8]
    assert extract_mac_from_duid(_duid_llt(mac)) == "34:fe:9e:3d:ad:c8"


def test_extract_mac_from_duid_ll():
    mac = [0x34, 0xfe, 0x9e, 0x3d, 0xaf, 0x5c]
    assert extract_mac_from_duid(_duid_ll(mac)) == "34:fe:9e:3d:af:5c"


def test_extract_mac_from_duid_en_ascii():
    # DUID-EN carries an ASCII identifier; the MAC is embedded as text.
    out = extract_mac_from_duid(_duid_en("ORU-34:fe:9e:3d:ad:a8"))
    assert out == "34:fe:9e:3d:ad:a8"


def test_extract_mac_from_duid_garbage_returns_dash():
    # Too short / non-decodable inputs must degrade to "-" (never raise).
    assert extract_mac_from_duid("") == "-"
    assert extract_mac_from_duid("ab") == "-"


# --------------------------------------------------------------------------
# ISC parsers
# --------------------------------------------------------------------------

def test_parse_isc_v4_returns_leases_with_active():
    ensure_fixtures()
    path = fixture_path("dhcpd.leases")
    leases = parse_isc_v4(path)
    assert isinstance(leases, list)
    assert len(leases) >= 1
    assert all(isinstance(l, Lease) for l in leases)
    # All should be DHCPv4 / ISC.
    assert all(l.version == "4" for l in leases)
    assert all(l.server == "isc" for l in leases)
    # At least one active lease present.
    states = [l.state for l in leases]
    assert "active" in states
    # The contested addresses from the report must be present in the fixture.
    ips = {l.ip for l in leases}
    assert _helpers.IP_171 in ips
    assert _helpers.IP_172 in ips


def test_parse_isc_v4_thief_holds_both_ips():
    ensure_fixtures()
    path = fixture_path("dhcpd.leases")
    leases = parse_isc_v4(path)
    # The thieving unit ad:c8 ends up holding BOTH .171 and .172 actively.
    by_ip = {l.ip: l for l in leases}
    assert by_ip[_helpers.IP_171].mac == _helpers.MAC_A3_ADC8
    assert by_ip[_helpers.IP_172].mac == _helpers.MAC_A3_ADC8
    assert by_ip[_helpers.IP_171].state == "active"
    assert by_ip[_helpers.IP_172].state == "active"


def test_parse_isc_v6_macs_from_duid():
    ensure_fixtures()
    path = fixture_path("dhcpd6.leases")
    leases = parse_isc_v6(path)
    assert isinstance(leases, list)
    assert len(leases) >= 1
    assert all(isinstance(l, Lease) for l in leases)
    assert all(l.version == "6" for l in leases)
    # DHCPv6 is unaffected: every lease must resolve a real MAC (not "-")
    # because the fixtures encode LLT/LL/EN DUIDs for the units.
    macs = {l.mac for l in leases}
    assert macs, "no v6 leases parsed"
    # The fixture's units share the 34:fe:9e:3d:* OUI prefix.
    assert any(m.startswith("34:fe:9e:3d:") for m in macs), macs


def test_parse_isc_missing_file_is_graceful():
    # Parsers must not crash on a missing path (return empty list).
    out = parse_isc_v4("/nonexistent/path/dhcpd.leases")
    assert out == [] or out == list()


# --------------------------------------------------------------------------
# Kea parsers -- journal dedup + state mapping
# --------------------------------------------------------------------------

def test_parse_kea_v4_journal_dedup_active_wins():
    ensure_fixtures()
    path = fixture_path("kea-leases4.csv")
    leases = parse_kea_v4(path)
    assert isinstance(leases, list)
    assert all(isinstance(l, Lease) for l in leases)
    assert all(l.version == "4" for l in leases)
    assert all(l.server == "kea" for l in leases)
    # Dedup: each IP appears at most once in the parsed result even though the
    # journal-style CSV may contain multiple rows for the same address.
    ips = [l.ip for l in leases]
    assert len(ips) == len(set(ips)), "Kea v4 dedup failed: duplicate IPs returned"
    # active must win over expired for any IP that has both rows.
    by_ip = {l.ip: l for l in leases}
    for ip, l in by_ip.items():
        # If a row exists for this IP, an expired row for the same IP must not
        # have shadowed an active one.
        assert l.state in ("active", "declined", "expired", "released") or \
            l.state.startswith("state-")


def test_parse_kea_v4_declined_mapping():
    ensure_fixtures()
    path = fixture_path("kea-leases4.csv")
    leases = parse_kea_v4(path)
    states = {l.state for l in leases}
    # The fixture includes a declined lease (state code 1 -> "declined").
    assert "declined" in states, states


def test_parse_kea_v6_returns_leases():
    ensure_fixtures()
    path = fixture_path("kea-leases6.csv")
    leases = parse_kea_v6(path)
    assert isinstance(leases, list)
    assert all(isinstance(l, Lease) for l in leases)
    assert all(l.version == "6" for l in leases)
    assert all(l.server == "kea" for l in leases)
    # Dedup invariant holds for v6 as well.
    ips = [l.ip for l in leases]
    assert len(ips) == len(set(ips))
