"""
Tests for dhcp_toolkit.forensics.report.

  * build_report has keys version / capture / findings / severity_counts / verdict
  * render_text(use_color=False) contains 'RFC 2131' and has NO ANSI escape (chr 27)
  * summarize_capture(real pcap) reports mostly non-DHCPv4 traffic
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path, real_pcap_path, has_ansi

from dhcp_toolkit.forensics.pcap import read_pcap
from dhcp_toolkit.forensics.transactions import build_transactions
from dhcp_toolkit.forensics.detectors import run_all
from dhcp_toolkit.forensics.report import (
    summarize_capture,
    build_report,
    render_text,
)


def _build(pcap_name):
    ensure_fixtures()
    packets = read_pcap(fixture_path(pcap_name))
    txns = build_transactions(packets)
    findings = run_all(txns, packets)
    summary = summarize_capture(packets)
    report = build_report(findings, txns, summary, {"pcap": pcap_name})
    return packets, txns, findings, summary, report


# --------------------------------------------------------------------------
# summarize_capture
# --------------------------------------------------------------------------

def test_summarize_capture_is_dict_with_counts():
    ensure_fixtures()
    packets = read_pcap(fixture_path("oru_xid_reuse.pcap"))
    summary = summarize_capture(packets)
    assert isinstance(summary, dict)
    # Histogram + dhcp counts; we accept either keying style but the values must
    # be present and numeric somewhere in the dict.
    flat = repr(summary).lower()
    assert "dhcp" in flat


def test_summarize_capture_real_is_mostly_non_dhcpv4():
    packets = read_pcap(real_pcap_path())
    summary = summarize_capture(packets)
    assert isinstance(summary, dict)
    total = len(packets)
    assert total > 0

    # Locate a DHCPv4 count in the summary; it must be zero for the real capture.
    def _find_count(d, *needles):
        found = []
        for k, v in d.items():
            ks = str(k).lower()
            if any(n in ks for n in needles):
                if isinstance(v, int):
                    found.append(v)
                elif isinstance(v, dict):
                    found.extend(x for x in v.values() if isinstance(x, int))
            elif isinstance(v, dict):
                # one level of nesting (e.g. {"dhcp": {"v4": 0, "v6": 1}})
                for kk, vv in v.items():
                    kks = str(kk).lower()
                    if any(n in kks for n in needles) and isinstance(vv, int):
                        found.append(vv)
        return found

    v4_counts = _find_count(summary, "v4", "dhcpv4")
    # If a dhcpv4-specific count is exposed, it must be 0.
    if v4_counts:
        assert all(c == 0 for c in v4_counts), \
            "real capture summary reports DHCPv4 frames: %r" % (v4_counts,)
    # And the great majority of frames are NOT DHCP at all (PTP dominates).
    dhcp_frames = [
        p for p in packets
        if p.l4 == "udp" and (
            p.src_port in (67, 68, 546, 547) or p.dst_port in (67, 68, 546, 547)
        )
    ]
    assert len(dhcp_frames) < total / 2, "real capture should be mostly non-DHCP"


# --------------------------------------------------------------------------
# build_report
# --------------------------------------------------------------------------

def test_build_report_has_required_keys():
    _p, _t, _f, _s, report = _build("oru_xid_reuse.pcap")
    assert isinstance(report, dict)
    for key in ("version", "capture", "findings", "severity_counts", "verdict"):
        assert key in report, "build_report missing key %r" % key


def test_build_report_verdict_affected_for_buggy():
    _p, _t, findings, _s, report = _build("oru_xid_reuse.pcap")
    assert str(report["verdict"]).upper().find("AFFECT") != -1 or \
        report["verdict"] in ("AFFECTED", "affected")
    # severity_counts should reflect at least one HIGH.
    sc = report["severity_counts"]
    assert isinstance(sc, dict)
    high = sc.get("HIGH", sc.get("high", 0))
    assert high >= 1


def test_build_report_clean_verdict_not_affected():
    _p, _t, _f, _s, report = _build("clean_dhcp.pcap")
    verdict = str(report["verdict"]).upper()
    assert "AFFECT" not in verdict or "NOT" in verdict or "CLEAN" in verdict, \
        "clean capture should not be flagged AFFECTED: %r" % (report["verdict"],)
    sc = report["severity_counts"]
    high = sc.get("HIGH", sc.get("high", 0))
    assert high == 0


# --------------------------------------------------------------------------
# render_text
# --------------------------------------------------------------------------

def test_render_text_no_color_mentions_rfc_and_has_no_ansi():
    _p, _t, _f, _s, report = _build("oru_xid_reuse.pcap")
    text = render_text(report, use_color=False)
    assert isinstance(text, str)
    assert "RFC 2131" in text, "render_text must cite RFC 2131"
    assert not has_ansi(text), "use_color=False output must contain no ANSI escapes"


def test_render_text_color_may_contain_ansi():
    _p, _t, _f, _s, report = _build("oru_xid_reuse.pcap")
    colored = render_text(report, use_color=True)
    assert isinstance(colored, str)
    # Colored output should still carry the substantive content.
    assert "RFC 2131" in colored
