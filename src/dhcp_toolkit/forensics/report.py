"""Build and render the forensic report.

``summarize_capture`` produces protocol histograms; ``build_report`` assembles
a JSON-serialisable dict from the findings, transactions and capture summary;
``render_text`` mirrors the bug-report structure as a plain-text (optionally
ANSI-coloured) report. Pure stdlib.
"""

from dataclasses import asdict

from .dhcp import decode_dhcpv4, decode_dhcpv6

REPORT_VERSION = '2.0.0'

# Ordering used wherever severities are listed.
_SEV_ORDER = ('HIGH', 'MEDIUM', 'LOW', 'INFO')

# Minimal ANSI palette (only used when use_color=True).
_ANSI = {
    'reset': '\x1b[0m', 'bold': '\x1b[1m', 'dim': '\x1b[2m',
    'red': '\x1b[31m', 'yellow': '\x1b[33m', 'green': '\x1b[32m',
    'cyan': '\x1b[36m', 'blue': '\x1b[34m',
}
_SEV_COLOR = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'cyan', 'INFO': 'dim'}


# --------------------------------------------------------------------------- #
# Capture summary.
# --------------------------------------------------------------------------- #
def summarize_capture(packets):
    """Return a histogram summary of a capture.

    Keys: ``total`` (int), ``ethertypes`` ({"0xXXXX": count}),
    ``dhcpv4`` / ``dhcpv6`` (decoded-message counts) and ``vlans``
    ({vlan_id_or_'none': count}).
    """
    ethertypes = {}
    vlans = {}
    dhcpv4 = 0
    dhcpv6 = 0
    total = 0

    for pkt in packets:
        total += 1
        et = '0x%04x' % (pkt.ethertype & 0xffff) if pkt.ethertype is not None \
            else '0x0000'
        ethertypes[et] = ethertypes.get(et, 0) + 1

        vkey = 'none' if pkt.vlan is None else str(pkt.vlan)
        vlans[vkey] = vlans.get(vkey, 0) + 1

        if pkt.l4 == 'udp':
            sp, dp = pkt.src_port, pkt.dst_port
            if sp in (67, 68) or dp in (67, 68):
                if decode_dhcpv4(pkt.payload) is not None:
                    dhcpv4 += 1
            elif sp in (546, 547) or dp in (546, 547):
                if decode_dhcpv6(pkt.payload) is not None:
                    dhcpv6 += 1

    return {
        'total': total,
        'ethertypes': ethertypes,
        'dhcpv4': dhcpv4,
        'dhcpv6': dhcpv6,
        'vlans': vlans,
    }


# --------------------------------------------------------------------------- #
# Report assembly.
# --------------------------------------------------------------------------- #
def _txn_to_dict(txn):
    """Compact, JSON-friendly view of a transaction with a packet timeline."""
    timeline = []
    for pkt, msg in txn.packets:
        row = {
            'ts': pkt.ts,
            'eth_src': pkt.eth_src,
            'eth_dst': pkt.eth_dst,
        }
        if txn.version == '4':
            row.update({
                'type': msg.msg_type_name,
                'chaddr': msg.chaddr,
                'ciaddr': msg.ciaddr,
                'yiaddr': msg.yiaddr,
                'requested_ip': msg.requested_ip,
                'client_id': None if msg.client_id is None
                else msg.client_id.hex(),
                'vendor_class': msg.vendor_class,
            })
        else:
            row.update({
                'type': msg.msg_type_name,
                'transaction_id': msg.transaction_id,
                'client_duid': msg.client_duid.hex()
                if msg.client_duid else None,
                'addresses': list(msg.addresses or []),
                'vendor_class': msg.vendor_class,
            })
        timeline.append(row)

    return {
        'key': txn.key,
        'version': txn.version,
        'xid': hex(txn.xid),
        'packet_count': len(txn.packets),
        'macs': list(txn.macs),
        'eth_srcs': list(txn.eth_srcs),
        'offered_ips': list(txn.offered_ips),
        'requested_ips': list(txn.requested_ips),
        'timeline': timeline,
    }


def build_report(findings, transactions, capture_summary, meta):
    """Assemble the full report dict."""
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    has_high = counts.get('HIGH', 0) > 0
    has_v4 = capture_summary.get('dhcpv4', 0) > 0 or \
        any(t.version == '4' for t in transactions)

    if has_high:
        verdict = 'AFFECTED'
    elif not has_v4:
        verdict = 'NO DHCPv4 TRAFFIC'
    else:
        verdict = 'CLEAN'

    return {
        'version': REPORT_VERSION,
        'generated_meta': dict(meta) if meta else {},
        'capture': capture_summary,
        'transactions': [_txn_to_dict(t) for t in transactions],
        'findings': [asdict(f) for f in findings],
        'severity_counts': counts,
        'verdict': verdict,
    }


# --------------------------------------------------------------------------- #
# Text rendering.
# --------------------------------------------------------------------------- #
def _c(use_color, color, text):
    if not use_color or color not in _ANSI:
        return text
    return _ANSI[color] + text + _ANSI['reset']


def _ts_str(ts):
    import time
    try:
        whole = int(ts)
        frac = ts - whole
        lt = time.gmtime(whole)
        return '%02d:%02d:%02d.%03d' % (lt.tm_hour, lt.tm_min, lt.tm_sec,
                                        int(round(frac * 1000)))
    except Exception:
        return str(ts)


def _rule(char='=', width=78):
    return char * width


def render_text(report, use_color=True):
    """Render ``report`` as plain text mirroring the bug-report structure."""
    out = []
    add = out.append

    meta = report.get('generated_meta', {})
    cap = report.get('capture', {})
    verdict = report.get('verdict', 'UNKNOWN')

    # ----- Header ----------------------------------------------------------- #
    add(_rule('='))
    add(_c(use_color, 'bold',
           'DHCP-ORU FORENSIC REPORT  (toolkit v%s)' % report.get('version', '?')))
    add(_rule('='))
    pcap_path = meta.get('pcap') or meta.get('path') or '-'
    add('Source pcap : %s' % pcap_path)
    if meta.get('generated_at'):
        add('Generated   : %s' % meta['generated_at'])
    if meta.get('note'):
        add('Note        : %s' % meta['note'])
    vcolor = 'red' if verdict == 'AFFECTED' else (
        'green' if verdict == 'CLEAN' else 'yellow')
    add('Verdict     : %s' % _c(use_color, vcolor, _c(use_color, 'bold', verdict)))
    add('')

    # ----- Capture summary -------------------------------------------------- #
    add(_c(use_color, 'bold', 'CAPTURE SUMMARY'))
    add(_rule('-'))
    add('Total frames : %d' % cap.get('total', 0))
    add('DHCPv4 msgs  : %d' % cap.get('dhcpv4', 0))
    add('DHCPv6 msgs  : %d' % cap.get('dhcpv6', 0))
    ets = cap.get('ethertypes', {})
    if ets:
        items = sorted(ets.items(), key=lambda kv: (-kv[1], kv[0]))
        add('Ethertypes   : ' + ', '.join('%s=%d' % (k, v) for k, v in items))
    vlans = cap.get('vlans', {})
    if vlans:
        items = sorted(vlans.items(), key=lambda kv: (-kv[1], kv[0]))
        add('VLANs        : ' + ', '.join('%s=%d' % (k, v) for k, v in items))
    add('')

    # ----- Per-transaction timelines --------------------------------------- #
    txns = report.get('transactions', [])
    add(_c(use_color, 'bold', 'TRANSACTIONS (%d)' % len(txns)))
    add(_rule('-'))
    if not txns:
        add('(no DHCP transactions decoded)')
    for txn in txns:
        ver = txn.get('version', '?')
        head = 'Transaction %s  [DHCPv%s]  packets=%d' % (
            txn.get('key'), ver, txn.get('packet_count', 0))
        add(_c(use_color, 'cyan', head))
        macs = txn.get('macs', [])
        if macs:
            label = 'duids' if ver == '6' else 'macs'
            add('  %-6s: %s' % (label, ', '.join(macs)))
        if txn.get('offered_ips'):
            add('  offered: %s' % ', '.join(txn['offered_ips']))
        # timeline table
        rows = txn.get('timeline', [])
        if rows:
            if ver == '4':
                add('  %-12s  %-17s  %-17s  %-8s  %-15s' %
                    ('time', 'eth_src', 'chaddr', 'type', 'ip'))
                add('  ' + _rule('-', 74))
                for r in rows:
                    ip = r.get('requested_ip') or _nonzero(r.get('yiaddr'))
                    add('  %-12s  %-17s  %-17s  %-8s  %-15s' % (
                        _ts_str(r.get('ts', 0)),
                        r.get('eth_src', '-'),
                        r.get('chaddr', '-'),
                        r.get('type', '?'),
                        ip or '-',
                    ))
            else:
                add('  %-12s  %-17s  %-12s  %s' %
                    ('time', 'eth_src', 'type', 'addresses'))
                add('  ' + _rule('-', 60))
                for r in rows:
                    addrs = ', '.join(r.get('addresses', []) or []) or '-'
                    add('  %-12s  %-17s  %-12s  %s' % (
                        _ts_str(r.get('ts', 0)),
                        r.get('eth_src', '-'),
                        r.get('type', '?'),
                        addrs,
                    ))
        add('')

    # ----- Findings grouped by severity ------------------------------------ #
    findings = report.get('findings', [])
    add(_c(use_color, 'bold', 'FINDINGS (%d)' % len(findings)))
    add(_rule('-'))
    if not findings:
        add(_c(use_color, 'green', 'No issues detected.'))
        add('')
    else:
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f.get('severity', 'INFO'), []).append(f)
        for sev in _SEV_ORDER:
            group = by_sev.get(sev)
            if not group:
                continue
            add(_c(use_color, _SEV_COLOR.get(sev, 'dim'),
                   '== %s (%d) ==' % (sev, len(group))))
            for f in group:
                add('  [%s] %s' % (f.get('id', '?'), _c(
                    use_color, 'bold', f.get('title', ''))))
                desc = f.get('description', '')
                for line in _wrap(desc, 72):
                    add('    ' + line)
                std = f.get('standards', [])
                if std:
                    add('    standards: ' + '; '.join(std))
                rec = f.get('recommendation', '')
                if rec:
                    rec_lines = _wrap(rec, 68)
                    if rec_lines:
                        add('    fix: ' + rec_lines[0])
                        for line in rec_lines[1:]:
                            add('          ' + line)
                evi = f.get('evidence', [])
                if evi:
                    add('    evidence:')
                    for e in evi:
                        add('      - ' + e)
                add('')

    # ----- Standards-violations table -------------------------------------- #
    add(_c(use_color, 'bold', 'STANDARDS VIOLATIONS'))
    add(_rule('-'))
    rows = _standards_rows(findings)
    if not rows:
        add('(none)')
    else:
        add('  %-9s  %-28s  %s' % ('severity', 'standard', 'finding'))
        add('  ' + _rule('-', 70))
        for sev, std, fid in rows:
            add('  %-9s  %-28s  %s' % (
                _c(use_color, _SEV_COLOR.get(sev, 'dim'), '%-9s' % sev)
                if use_color else '%-9s' % sev,
                std, fid))
    add('')

    # ----- Verdict footer --------------------------------------------------- #
    add(_rule('='))
    counts = report.get('severity_counts', {})
    summary = ', '.join('%s=%d' % (s, counts.get(s, 0)) for s in _SEV_ORDER)
    add('VERDICT: %s   (%s)' % (
        _c(use_color, vcolor, _c(use_color, 'bold', verdict)), summary))
    add(_rule('='))

    return '\n'.join(out)


def _nonzero(ip):
    if not ip or ip in ('0.0.0.0', '::'):
        return None
    return ip


def _standards_rows(findings):
    rows = []
    seen = set()
    order = {s: i for i, s in enumerate(_SEV_ORDER)}
    for f in findings:
        for std in f.get('standards', []):
            key = (f.get('severity'), std, f.get('id'))
            if key in seen:
                continue
            seen.add(key)
            rows.append((f.get('severity', 'INFO'), std, f.get('id', '?')))
    rows.sort(key=lambda r: (order.get(r[0], 9), r[1], r[2]))
    return rows


def _wrap(text, width):
    if not text:
        return []
    words = text.split()
    lines = []
    cur = ''
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w) if cur else w
    if cur:
        lines.append(cur)
    return lines
