"""
End-to-end CLI tests (subprocess), exercising the real entrypoints.

forensics CLI:
  * on the buggy capture  -> exit code 2, output contains AFFECTED / HIGH
  * on the clean capture  -> exit code 0

leases CLI:
  * --v4-lease <fixture> --v4-only prints the leases (contested IPs visible)
  * --conflicts on the broken leases exits 2
"""

import os
import sys
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path, REPO_ROOT, SRC_DIR


def _run(module, *args):
    """Run `python -m <module> <args...>` with PYTHONPATH=src; capture output."""
    env = dict(os.environ)
    # Ensure src is importable for the child process.
    existing = env.get("PYTHONPATH", "")
    parts = [SRC_DIR]
    if existing:
        parts.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env.setdefault("NO_COLOR", "1")
    proc = subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


# --------------------------------------------------------------------------
# forensics CLI
# --------------------------------------------------------------------------

def test_forensics_cli_buggy_exits_2_and_reports_affected():
    ensure_fixtures()
    pcap = fixture_path("oru_xid_reuse.pcap")
    code, out = _run("dhcp_toolkit.forensics.cli", pcap, "--no-color")
    assert code == 2, "expected exit 2 on buggy capture, got %d\n%s" % (code, out)
    up = out.upper()
    assert "AFFECTED" in up or "HIGH" in up, \
        "forensics output should flag AFFECTED/HIGH:\n%s" % out


def test_forensics_cli_buggy_cites_rfc():
    ensure_fixtures()
    pcap = fixture_path("oru_xid_reuse.pcap")
    code, out = _run("dhcp_toolkit.forensics.cli", pcap, "--no-color")
    assert "RFC 2131" in out, "forensics text report should cite RFC 2131:\n%s" % out


def test_forensics_cli_json_mode():
    ensure_fixtures()
    pcap = fixture_path("oru_xid_reuse.pcap")
    code, out = _run("dhcp_toolkit.forensics.cli", pcap, "--json", "--no-color")
    assert code == 2, "json mode should still exit 2 on buggy capture"
    # Output should be parseable JSON containing the expected keys.
    import json
    # Some CLIs print a leading banner; find the JSON object boundary.
    start = out.find("{")
    assert start != -1, "no JSON object found in --json output:\n%s" % out
    obj = json.loads(out[start:])
    assert "verdict" in obj
    assert "findings" in obj


def test_forensics_cli_clean_exits_0():
    ensure_fixtures()
    pcap = fixture_path("clean_dhcp.pcap")
    code, out = _run("dhcp_toolkit.forensics.cli", pcap, "--no-color")
    assert code == 0, "expected exit 0 on clean capture, got %d\n%s" % (code, out)


def test_forensics_cli_real_capture_runs():
    # The genuine capture has no DHCPv4 -> not AFFECTED -> exit 0, no crash.
    pcap = _helpers.real_pcap_path()
    code, out = _run("dhcp_toolkit.forensics.cli", pcap, "--no-color")
    assert code == 0, "real capture should exit 0 (no HIGH findings)\n%s" % out


# --------------------------------------------------------------------------
# leases CLI
# --------------------------------------------------------------------------

def test_leases_cli_v4_only_prints_leases():
    ensure_fixtures()
    lease = fixture_path("dhcpd.leases")
    code, out = _run(
        "dhcp_toolkit.leases.cli",
        "--v4-lease", lease, "--v4-only", "--all",
    )
    assert code == 0, "leases --v4-only should exit 0, got %d\n%s" % (code, out)
    # The contested addresses must be visible in the printed table.
    assert _helpers.IP_171 in out, out
    assert _helpers.IP_172 in out, out


def test_leases_cli_version():
    from dhcp_toolkit import __version__
    code, out = _run("dhcp_toolkit.leases.cli", "--version")
    assert code == 0
    assert __version__ in out, out


def test_leases_cli_autodetects_kea_from_the_lease_file():
    # No --server flag: the CSV format identifies Kea on its own.
    ensure_fixtures()
    lease = fixture_path("kea-leases4.csv")
    code, out = _run(
        "dhcp_toolkit.leases.cli",
        "--v4-lease", lease, "--v4-only", "--all",
    )
    assert code == 0, out
    assert "Kea" in out, out
    assert "192.168.36.170" in out, out


def test_leases_cli_server_kea_still_works():
    ensure_fixtures()
    code, out = _run(
        "dhcp_toolkit.leases.cli", "--server", "kea",
        "--v4-lease", fixture_path("kea-leases4.csv"),
        "--v6-lease", fixture_path("kea-leases6.csv"), "--all",
    )
    assert code == 0, out
    # The v6 unit whose hwaddr column is empty is still identified by MAC.
    assert "34:fe:9e:3d:ad:c8" in out, out


def test_leases_cli_server_both_prints_a_section_per_server():
    ensure_fixtures()
    code, out = _run("dhcp_toolkit.leases.cli", "--server", "both", "--v4-only")
    assert code == 0, out
    assert "--- ISC DHCP ---" in out, out
    assert "--- Kea DHCP ---" in out, out


def test_leases_cli_reports_a_non_memfile_kea_backend():
    # A MySQL lease backend has no CSV to read; the user gets told why the
    # table is empty instead of being left guessing.
    ensure_fixtures()
    kea_etc = os.path.dirname(fixture_path("kea-dhcp4.conf"))
    code, out = _run("dhcp_toolkit.leases.cli", "--server", "kea",
                     "--kea-config-dir", kea_etc, "--v6-only")
    assert code == 0, out
    assert "mysql" in out, out


def test_leases_cli_conflicts_exits_2_on_broken():
    ensure_fixtures()
    lease = fixture_path("dhcpd.leases")
    code, out = _run(
        "dhcp_toolkit.leases.cli",
        "--v4-lease", lease, "--v4-only", "--conflicts",
    )
    assert code == 2, "--conflicts on broken leases must exit 2, got %d\n%s" % (
        code, out,
    )
    # The conflict report should name the thieving unit and HIGH severity.
    up = out.upper()
    assert "HIGH" in up or "CONFLICT" in up, out
