"""Command-line entrypoint for the DHCP-ORU forensic analyzer.

Usage::

    dhcp-forensics PCAP [--json] [--leases FILE] [--config FILE] [--no-color]

Reads a pcap, decodes DHCPv4/v6, groups packets into transactions, runs the
detectors and prints (or emits as JSON) the forensic report. Optionally folds
in lease-file conflicts and notes configured pools. Exit code is 0 when no HIGH
finding is present, otherwise 2. Pure stdlib.
"""

import argparse
import json
import sys

from .pcap import read_pcap
from .transactions import build_transactions
from .detectors import run_all
from .report import summarize_capture, build_report, render_text
from .models import Finding


def _build_parser():
    p = argparse.ArgumentParser(
        prog='dhcp-forensics',
        description='Analyze a pcap for the O-RU shared-xid DHCPv4 defect.',
    )
    p.add_argument('pcap', metavar='PCAP',
                   help='capture file (classic pcap or minimal pcapng)')
    p.add_argument('--json', action='store_true',
                   help='print the report as JSON instead of text')
    p.add_argument('--leases', metavar='FILE', default=None,
                   help='also parse this lease file and fold conflicts in')
    p.add_argument('--config', metavar='FILE', default=None,
                   help='ISC dhcpd config to note configured pools')
    p.add_argument('--no-color', action='store_true',
                   help='disable ANSI colour in text output')
    return p


def _parse_leases(path):
    """Best-effort parse of a lease file across ISC/Kea, v4/v6.

    Returns ``(leases, label)``; tries every parser and keeps whichever yields
    the most leases so we do not need the caller to declare the format.
    """
    try:
        from ..leases import parsers as lp
    except Exception:
        return [], None

    candidates = []
    for name in ('parse_isc_v4', 'parse_isc_v6', 'parse_kea_v4', 'parse_kea_v6'):
        fn = getattr(lp, name, None)
        if fn is None:
            continue
        try:
            leases = fn(path)
        except Exception:
            leases = None
        if leases:
            candidates.append((len(leases), name, leases))
    if not candidates:
        return [], None
    candidates.sort(key=lambda c: c[0], reverse=True)
    _n, name, leases = candidates[0]
    return leases, name


def _lease_conflicts_to_findings(path):
    """Parse a lease file and convert any conflicts into Findings."""
    leases, label = _parse_leases(path)
    if not leases:
        return []
    try:
        from ..leases.conflicts import find_conflicts
    except Exception:
        return []
    try:
        conflicts = find_conflicts(leases)
    except Exception:
        conflicts = []

    findings = []
    for c in conflicts:
        sev = getattr(c, 'severity', 'MEDIUM') or 'MEDIUM'
        kind = getattr(c, 'kind', 'lease_conflict')
        detail = getattr(c, 'detail', '')
        ips = getattr(c, 'ips', []) or []
        macs = getattr(c, 'macs', []) or []
        evidence = []
        if ips:
            evidence.append('ips: ' + ', '.join(map(str, ips)))
        if macs:
            evidence.append('macs: ' + ', '.join(map(str, macs)))
        findings.append(Finding(
            id='LEASE_' + str(kind).upper(),
            title='Lease-file conflict: %s' % kind,
            severity=sev,
            category='lease-conflict',
            description=detail or ('Conflict %s found in lease file %s'
                                   % (kind, path)),
            evidence=evidence,
            standards=['RFC 2131 section 4.3.1'],
            recommendation=('Resolve the duplicate/overlapping lease '
                            'allocation in the DHCP server state.'),
        ))
    return findings


def _config_pools(path):
    """Extract a lightweight list of pool/range notes from an ISC dhcpd config."""
    pools = []
    try:
        with open(path, 'r', errors='replace') as fh:
            for line in fh:
                s = line.strip()
                low = s.lower()
                if low.startswith('range') or low.startswith('subnet') \
                        or low.startswith('range6'):
                    pools.append(s.rstrip(';'))
    except OSError:
        return []
    return pools


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    use_color = not args.no_color

    try:
        packets = read_pcap(args.pcap)
    except FileNotFoundError:
        sys.stderr.write('error: pcap not found: %s\n' % args.pcap)
        return 2
    except Exception as exc:  # noqa: BLE001 - report cleanly, never crash
        sys.stderr.write('error: failed to read pcap: %s\n' % exc)
        return 2

    transactions = build_transactions(packets)
    findings = run_all(transactions, packets)

    # Fold lease-file conflicts into the findings list.
    if args.leases:
        findings = findings + _lease_conflicts_to_findings(args.leases)

    capture_summary = summarize_capture(packets)

    meta = {
        'pcap': args.pcap,
        'tool': 'dhcp-forensics',
    }
    if args.leases:
        meta['leases'] = args.leases
    if args.config:
        pools = _config_pools(args.config)
        meta['config'] = args.config
        if pools:
            meta['config_pools'] = pools

    # Honest note when the capture holds no DHCPv4 (e.g. the real O-RU pcap).
    if capture_summary.get('dhcpv4', 0) == 0:
        meta['note'] = ('capture contains no DHCPv4 traffic; '
                        'DHCPv4 defect cannot be observed in this file')

    report = build_report(findings, transactions, capture_summary, meta)

    if args.json:
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=False))
        sys.stdout.write('\n')
    else:
        sys.stdout.write(render_text(report, use_color=use_color))
        sys.stdout.write('\n')

    has_high = report.get('severity_counts', {}).get('HIGH', 0) > 0
    return 2 if has_high else 0


if __name__ == '__main__':
    sys.exit(main())
