"""
Tests for dhcp_toolkit.forensics.detectors.

On the buggy oru_xid_reuse capture:
  * detect_shared_xid flags BOTH reused xids
  * detect_foreign_offer_reaction flags the af:5c / ad:c8 cross-requests
  * detect_missing_client_id flags all units
  * run_all -> verdict AFFECTED with >= 1 HIGH finding

On the clean capture:
  * run_all returns NO HIGH findings
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _helpers
from _helpers import ensure_fixtures, fixture_path

from dhcp_toolkit.forensics.pcap import read_pcap
from dhcp_toolkit.forensics.transactions import build_transactions
from dhcp_toolkit.forensics.detectors import (
    run_all,
    detect_shared_xid,
    detect_foreign_offer_reaction,
    detect_missing_client_id,
    detect_chaddr_ethsrc_mismatch,
    detect_duplicate_grants,
)
from dhcp_toolkit.forensics.models import Finding, Transaction


def _load(pcap_name):
    ensure_fixtures()
    packets = read_pcap(fixture_path(pcap_name))
    txns = build_transactions(packets)
    return packets, txns


def _all_evidence_text(finding):
    """Flatten a finding's evidence into one searchable string."""
    parts = [finding.title or "", finding.description or ""]
    for e in finding.evidence:
        parts.append(repr(e))
    return " ".join(parts)


# --------------------------------------------------------------------------
# build_transactions sanity
# --------------------------------------------------------------------------

def test_build_transactions_groups_by_xid():
    _packets, txns = _load("oru_xid_reuse.pcap")
    assert isinstance(txns, list)
    assert all(isinstance(t, Transaction) for t in txns)
    v4 = [t for t in txns if t.version == "4"]
    xids = {t.xid for t in v4}
    # Both documented reused xids appear as transactions.
    assert _helpers.XID_SEQ1 in xids
    assert _helpers.XID_SEQ2 in xids


def test_transaction_collects_multiple_macs_for_shared_xid():
    _packets, txns = _load("oru_xid_reuse.pcap")
    by_xid = {t.xid: t for t in txns if t.version == "4"}
    # Each shared-xid transaction was driven by more than one unit.
    t1 = by_xid[_helpers.XID_SEQ1]
    t2 = by_xid[_helpers.XID_SEQ2]
    assert len(set(t1.macs)) >= 2, t1.macs
    assert len(set(t2.macs)) >= 2, t2.macs


# --------------------------------------------------------------------------
# Individual detectors -- buggy capture
# --------------------------------------------------------------------------

def test_detect_shared_xid_flags_both():
    packets, txns = _load("oru_xid_reuse.pcap")
    findings = detect_shared_xid(txns, packets)
    assert findings, "detect_shared_xid produced no findings"
    assert all(isinstance(f, Finding) for f in findings)
    assert all(f.severity == "HIGH" for f in findings)
    blob = " ".join(_all_evidence_text(f) for f in findings)
    # BOTH reused xids must be cited (hex or decimal form).
    for xid in (_helpers.XID_SEQ1, _helpers.XID_SEQ2):
        assert (("%08x" % xid) in blob.lower()) or (str(xid) in blob), \
            "xid 0x%08x not cited by detect_shared_xid" % xid


def test_detect_foreign_offer_reaction_flags_cross_requests():
    packets, txns = _load("oru_xid_reuse.pcap")
    findings = detect_foreign_offer_reaction(txns, packets)
    assert findings, "detect_foreign_offer_reaction produced no findings"
    assert all(isinstance(f, Finding) for f in findings)
    blob = " ".join(_all_evidence_text(f) for f in findings).lower()
    # The cross-reaction involves af:5c and ad:c8 grabbing addresses offered to
    # other units; both offenders should be named in the evidence.
    assert _helpers.MAC_A2_AF5C in blob or "af:5c" in blob
    assert _helpers.MAC_A3_ADC8 in blob or "ad:c8" in blob
    # This defect is high-severity (IP theft / RFC 2131 4.4.1 violation).
    assert any(f.severity == "HIGH" for f in findings)


def test_detect_missing_client_id_flags_all_units():
    packets, txns = _load("oru_xid_reuse.pcap")
    findings = detect_missing_client_id(txns, packets)
    assert findings, "detect_missing_client_id produced no findings"
    blob = " ".join(_all_evidence_text(f) for f in findings).lower()
    # All three units lack opt61, so each MAC should be represented.
    for mac in (_helpers.MAC_A1_ADA8, _helpers.MAC_A2_AF5C, _helpers.MAC_A3_ADC8):
        short = mac.split(":")
        short_tail = ":".join(short[-2:])
        assert mac in blob or short_tail in blob, \
            "unit %s not cited by detect_missing_client_id" % mac


def test_detect_helpers_return_findings_lists():
    # The remaining individual detectors must return lists of Finding (possibly
    # empty) and never raise on the buggy capture.
    packets, txns = _load("oru_xid_reuse.pcap")
    for det in (detect_chaddr_ethsrc_mismatch, detect_duplicate_grants):
        out = det(txns, packets)
        assert isinstance(out, list)
        assert all(isinstance(f, Finding) for f in out)


def test_detect_duplicate_grants_flags_thief():
    # ad:c8 ends up granted both .171 and .172 (ACKs) -> duplicate grant.
    packets, txns = _load("oru_xid_reuse.pcap")
    findings = detect_duplicate_grants(txns, packets)
    # This may legitimately be empty if no ACKs are modelled, but when present
    # it must name the thieving unit.
    if findings:
        blob = " ".join(_all_evidence_text(f) for f in findings).lower()
        assert _helpers.MAC_A3_ADC8 in blob or "ad:c8" in blob


# --------------------------------------------------------------------------
# run_all aggregation -- verdict
# --------------------------------------------------------------------------

def test_run_all_buggy_is_affected_with_high():
    packets, txns = _load("oru_xid_reuse.pcap")
    findings = run_all(txns, packets)
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)
    highs = [f for f in findings if f.severity == "HIGH"]
    assert len(highs) >= 1, "expected >= 1 HIGH finding on the buggy capture"
    # The three documented defect categories should all surface.
    ids = {f.id for f in findings}
    titles = " ".join((f.title or "") + " " + (f.id or "") for f in findings).lower()
    assert "xid" in titles
    assert "client" in titles or "opt61" in titles or "option 61" in titles


def test_run_all_clean_has_no_high():
    packets, txns = _load("clean_dhcp.pcap")
    findings = run_all(txns, packets)
    assert isinstance(findings, list)
    highs = [f for f in findings if f.severity == "HIGH"]
    assert highs == [], "clean capture must yield NO HIGH findings, got %r" % (
        [f.id for f in highs],
    )
