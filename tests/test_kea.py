"""
Tests for the Kea DHCP support in dhcp_toolkit.leases.

Everything here covers a way the viewer used to work on ISC but not on Kea:

  * Kea memfile journal semantics -- last row wins, valid_lifetime 0 deletes.
  * Lease File Cleanup (LFC) generations (.1/.2/.completed) being read.
  * MAC recovery from a DHCPv6 DUID and a DHCPv4 option 61 client-id when Kea
    left the hwaddr column empty.
  * Lease expiry rendered in UTC rather than the server's local time.
  * Kea config discovery: comments, <?include?>, non-default memfile paths and
    non-memfile lease backends.
  * Server auto-detection in the CLI.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path

from dhcp_toolkit.leases.parsers import (
    parse_kea_v4,
    parse_kea_v6,
    kea_lease_files,
    epoch_to_datetime,
    hex_to_bytes,
    kea_unescape,
    mac_from_duid_bytes,
    mac_from_kea_duid,
    mac_from_kea_client_id,
)
from dhcp_toolkit.leases.display import is_expired
from dhcp_toolkit.leases import kea_config
from dhcp_toolkit.leases.cli import sniff_server, detect_servers, kea_lease_path


VENDOR_CLASS = "o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222"


def _by_ip(leases):
    return {l.ip: l for l in leases}


def _kea_etc():
    """Directory of the Kea config fixtures."""
    return os.path.dirname(fixture_path("kea-dhcp4.conf"))


# --------------------------------------------------------------------------
# Journal semantics: last row wins, valid_lifetime 0 deletes
# --------------------------------------------------------------------------

def test_kea_v4_released_after_active_is_released():
    # Kea replays its lease file in order, so a release recorded after the
    # binding is the truth. An "active always wins" dedup kept showing the
    # address as held by a unit that had given it up.
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    assert "192.168.36.173" in by_ip
    assert by_ip["192.168.36.173"].state == "released", by_ip["192.168.36.173"]


def test_kea_v4_zero_valid_lifetime_deletes_the_lease():
    # valid_lifetime 0 is Kea's delete marker; the address must disappear.
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    assert "192.168.36.174" not in by_ip, "deleted lease still listed"


def test_kea_v4_expired_row_then_active_row_is_active():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    assert by_ip["192.168.36.171"].state == "active"


# --------------------------------------------------------------------------
# Lease File Cleanup generations
# --------------------------------------------------------------------------

def test_kea_lease_files_lists_lfc_generations_oldest_first():
    ensure_fixtures()
    primary = fixture_path("kea-lfc-leases4.csv")
    files = kea_lease_files(primary)
    assert files[-1] == primary, "primary file must be replayed last"
    assert files == [primary + ".2", primary + ".1", primary], files


def test_kea_lease_files_of_missing_path_is_empty():
    assert kea_lease_files("/nonexistent/kea-leases4.csv") == []


def test_kea_v4_reads_leases_out_of_lfc_generations():
    # Mid-cleanup most leases are in .2/.1, not in the primary file. Reading
    # only the primary reported one lease out of three.
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-lfc-leases4.csv")))
    assert set(by_ip) == {"192.168.36.190", "192.168.36.191", "192.168.36.192"}, by_ip


def test_kea_lfc_generations_are_ordered_newest_last():
    # .191 is bound in .2 and released in .1: the newer generation must win.
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-lfc-leases4.csv")))
    assert by_ip["192.168.36.191"].state == "released"
    assert by_ip["192.168.36.190"].state == "active"


def test_kea_completed_file_supersedes_numbered_generations():
    # When a cleanup finished, Kea leaves a .completed file; it is loaded in
    # place of the .1/.2 pair.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "kea-leases4.csv")
        header = ("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"
                  "fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n")
        for suffix, ip in ((".completed", "10.0.0.1"), (".1", "10.0.0.2"),
                           (".2", "10.0.0.3"), ("", "10.0.0.4")):
            with open(base + suffix, "w") as fh:
                fh.write(header)
                fh.write("%s,34:fe:9e:3d:ad:a8,,3600,4102444800,1,0,0,,0,,0\n" % ip)

        files = kea_lease_files(base)
        assert files == [base + ".completed", base], files
        ips = {l.ip for l in parse_kea_v4(base)}
        assert ips == {"10.0.0.1", "10.0.0.4"}, ips


# --------------------------------------------------------------------------
# MAC recovery when Kea left the hwaddr column empty
# --------------------------------------------------------------------------

def test_kea_v6_mac_from_duid_llt_when_hwaddr_empty():
    # Kea only fills hwaddr when it could derive a link-layer address; with an
    # empty column the DUID is the only place the MAC lives.
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v6(fixture_path("kea-leases6.csv")))
    assert by_ip["fd00:36::173"].mac == "34:fe:9e:3d:ad:c8"


def test_kea_v6_mac_from_duid_ll_when_hwaddr_empty():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v6(fixture_path("kea-leases6.csv")))
    assert by_ip["fd00:36::174"].mac == "34:fe:9e:3d:ad:44"


def test_kea_v6_mac_from_oran_duid_en_when_hwaddr_empty():
    # O-RAN units use DUID-EN (enterprise 53148) with the MAC written as ASCII.
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v6(fixture_path("kea-leases6.csv")))
    assert by_ip["fd00:36::175"].mac == "34:fe:9e:3d:ad:55"


def test_kea_v6_prefers_the_hwaddr_column_when_present():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v6(fixture_path("kea-leases6.csv")))
    assert by_ip["fd00:36::171"].mac == "34:fe:9e:3d:ad:a8"


def test_kea_v6_skips_prefix_delegation_rows():
    ensure_fixtures()
    ips = {l.ip for l in parse_kea_v6(fixture_path("kea-leases6.csv"))}
    assert "fd00:36:abcd::" not in ips


def test_kea_v4_mac_from_client_id_when_hwaddr_empty():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    assert by_ip["192.168.36.175"].mac == "34:fe:9e:3d:ad:22"


def test_mac_from_kea_client_id_encodings():
    # RFC 2132 htype+MAC, RFC 4361 type 255 + IAID + DUID, and a bare MAC.
    assert mac_from_kea_client_id("01:34:fe:9e:3d:ad:22") == "34:fe:9e:3d:ad:22"
    assert mac_from_kea_client_id(
        "ff:00:00:00:01:00:03:00:01:34:fe:9e:3d:ad:33") == "34:fe:9e:3d:ad:33"
    assert mac_from_kea_client_id("34:fe:9e:3d:ad:44") == "34:fe:9e:3d:ad:44"
    # An opaque string client-id carries no MAC.
    assert mac_from_kea_client_id("00:6f:72:75") == "-"
    assert mac_from_kea_client_id("") == "-"
    assert mac_from_kea_client_id("not hex") == "-"


def test_mac_from_kea_duid_matches_the_isc_decoder():
    # Kea stores the bare DUID as colon hex; ISC prefixes a 4-byte IAID. Both
    # must yield the same MAC for the same unit.
    assert mac_from_kea_duid(
        "00:01:00:01:29:a4:f3:00:34:fe:9e:3d:ad:a8") == "34:fe:9e:3d:ad:a8"
    assert mac_from_kea_duid("00:03:00:01:34:fe:9e:3d:af:5c") == "34:fe:9e:3d:af:5c"
    assert mac_from_kea_duid("") == "-"
    assert mac_from_kea_duid("00:04:de:ad") == "-"


def test_mac_from_duid_bytes_is_defensive():
    assert mac_from_duid_bytes(b"") == "-"
    assert mac_from_duid_bytes(b"\x00") == "-"
    assert mac_from_duid_bytes(b"\x00\x01") == "-"      # LLT, truncated


def test_hex_to_bytes_tolerates_separators_and_junk():
    assert hex_to_bytes("34:fe:9e") == b"\x34\xfe\x9e"
    assert hex_to_bytes("34-fe-9e") == b"\x34\xfe\x9e"
    assert hex_to_bytes("34fe9e") == b"\x34\xfe\x9e"
    assert hex_to_bytes("") == b""
    assert hex_to_bytes("zz") == b""
    assert hex_to_bytes("abc") == b""                    # odd length


# --------------------------------------------------------------------------
# user-context / CSV escaping
# --------------------------------------------------------------------------

def test_kea_v4_vendor_class_from_user_context():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    assert by_ip["192.168.36.176"].vendor_class == VENDOR_CLASS


def test_kea_unescape_decodes_hex_entities():
    assert kea_unescape("a&#x2c;b") == "a,b"
    assert kea_unescape("plain") == "plain"
    assert kea_unescape("") == ""


def test_kea_v4_missing_user_context_leaves_vendor_class_blank():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    assert by_ip["192.168.36.170"].vendor_class == "-"


# --------------------------------------------------------------------------
# UTC timestamps
# --------------------------------------------------------------------------

def test_epoch_to_datetime_is_utc_regardless_of_local_timezone():
    # Kea records expiry as an epoch. Rendering it with the server's local
    # clock put the Kea column hours away from the ISC one, under a heading
    # that says UTC for both.
    import time
    original = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "Asia/Tokyo"          # UTC+9, no DST
        time.tzset()
        assert epoch_to_datetime("0") == "1970/01/01 00:00:00"
        assert epoch_to_datetime("4102444800") == "2100/01/01 00:00:00"
    finally:
        if original is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original
        time.tzset()


def test_epoch_to_datetime_rejects_junk():
    assert epoch_to_datetime("") == "-"
    assert epoch_to_datetime("not-a-number") == "-"
    assert epoch_to_datetime(None) == "-"


def test_is_expired_compares_against_utc():
    import time
    original = os.environ.get("TZ")
    try:
        # East of Greenwich the local clock runs ahead of the lease's UTC
        # stamp, which used to make still-valid leases look expired.
        os.environ["TZ"] = "Asia/Tokyo"
        time.tzset()
        assert is_expired("2100/01/01 00:00:00") is False
        assert is_expired("1999/01/01 00:00:00") is True
        assert is_expired("-") is False
    finally:
        if original is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original
        time.tzset()


def test_kea_starts_is_expiry_minus_lifetime():
    ensure_fixtures()
    by_ip = _by_ip(parse_kea_v4(fixture_path("kea-leases4.csv")))
    # expire 4102444800 (2100/01/01) minus a 3600s lifetime.
    assert by_ip["192.168.36.170"].starts == "2099/12/31 23:00:00"


# --------------------------------------------------------------------------
# Kea config discovery
# --------------------------------------------------------------------------

def test_strip_json_comments_handles_all_three_comment_styles():
    text = '{"a": 1, // line\n "b": 2, # hash\n /* block */ "c": 3}'
    assert kea_config.strip_json_comments(text).replace("\n", " ").split() == \
        '{"a": 1,   "b": 2,    "c": 3}'.split()


def test_strip_json_comments_leaves_string_contents_alone():
    text = '{"url": "http://example/x", "note": "# not a comment"}'
    import json
    obj = json.loads(kea_config.strip_json_comments(text))
    assert obj["url"] == "http://example/x"
    assert obj["note"] == "# not a comment"


def test_discover_memfile_path_from_config():
    # The lease file is wherever lease-database.name says, not the default.
    ensure_fixtures()
    source = kea_config.discover_lease_source("4", _kea_etc())
    assert source.backend == "memfile"
    assert source.path == "/var/lib/kea/oran-leases4.csv"
    assert source.readable is True


def test_discover_reports_non_memfile_backend():
    # A MySQL/PostgreSQL lease backend has no CSV; say so rather than printing
    # an empty table.
    ensure_fixtures()
    source = kea_config.discover_lease_source("6", _kea_etc())
    assert source.backend == "mysql"
    assert source.readable is False
    assert source.note and "mysql" in source.note


def test_discover_falls_back_to_default_without_config():
    source = kea_config.discover_lease_source("4", "/nonexistent/etc/kea")
    assert source.path == kea_config.DEFAULT_KEA_V4
    assert source.readable is True


def test_discover_falls_back_when_config_is_unparseable():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "kea-dhcp4.conf"), "w") as fh:
            fh.write('{"Dhcp4": {')          # truncated JSON
        source = kea_config.discover_lease_source("4", d)
        assert source.path == kea_config.DEFAULT_KEA_V4
        assert source.note and "parse" in source.note


def test_discover_flags_non_persistent_memfile():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "kea-dhcp4.conf"), "w") as fh:
            fh.write('{"Dhcp4": {"lease-database": '
                     '{"type": "memfile", "persist": false}}}')
        source = kea_config.discover_lease_source("4", d)
        assert source.readable is False
        assert source.note and "persist" in source.note


def test_expand_includes_inlines_the_referenced_file():
    # <?include?> is a Kea extension; the config is not valid JSON until it is
    # expanded.
    ensure_fixtures()
    cfg = kea_config.read_kea_config(fixture_path("kea-dhcp4.conf"))
    assert cfg is not None, "config with comments + <?include?> failed to parse"
    assert cfg["Dhcp4"]["subnet4"][0]["subnet"] == "192.168.36.0/24"


def test_find_config_returns_none_when_absent():
    assert kea_config.find_config("4", "/nonexistent/etc/kea") is None


# --------------------------------------------------------------------------
# CLI: format sniffing, server detection, path resolution
# --------------------------------------------------------------------------

def test_sniff_server_identifies_both_formats():
    ensure_fixtures()
    assert sniff_server(fixture_path("kea-leases4.csv")) == "kea"
    assert sniff_server(fixture_path("kea-leases6.csv")) == "kea"
    assert sniff_server(fixture_path("dhcpd.leases")) == "isc"
    assert sniff_server(fixture_path("dhcpd6.leases")) == "isc"
    assert sniff_server("/nonexistent/leases") is None


class _Args:
    """Stand-in for the parsed argparse namespace."""
    def __init__(self, v4_lease=None, v6_lease=None):
        self.v4_lease = v4_lease
        self.v6_lease = v6_lease


def test_detect_servers_sniffs_an_explicit_lease_file():
    # `dhcp-lease-list --v4-lease kea-leases4.csv` must not need --server kea.
    ensure_fixtures()
    assert detect_servers(_Args(v4_lease=fixture_path("kea-leases4.csv")),
                          ("/nonexistent",)) == ["kea"]
    assert detect_servers(_Args(v4_lease=fixture_path("dhcpd.leases")),
                          ("/nonexistent",)) == ["isc"]


def test_detect_servers_finds_kea_from_its_config_dir():
    ensure_fixtures()
    assert detect_servers(_Args(), (_kea_etc(),)) == ["kea"]


def test_detect_servers_defaults_to_isc_when_nothing_is_installed():
    # Preserves the historical behaviour of a bare invocation on a bare host.
    assert detect_servers(_Args(), ("/nonexistent/etc/kea",)) == ["isc"]


def test_kea_lease_path_prefers_an_explicit_override():
    ensure_fixtures()
    path, note = kea_lease_path("4", "/tmp/custom.csv", (_kea_etc(),))
    assert path == "/tmp/custom.csv"
    assert note is None


def test_kea_lease_path_uses_the_configured_memfile_path():
    ensure_fixtures()
    path, note = kea_lease_path("4", None, (_kea_etc(),))
    assert path == "/var/lib/kea/oran-leases4.csv"


def test_kea_lease_path_surfaces_the_backend_note():
    ensure_fixtures()
    path, note = kea_lease_path("6", None, (_kea_etc(),))
    assert note and "mysql" in note
