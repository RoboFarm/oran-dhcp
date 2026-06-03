"""Detectors that turn grouped DHCP transactions into :class:`Finding` objects.

Each detector encodes one of the documented O-RU DHCPv4 defects and returns a
list of findings with precise per-packet evidence and the relevant standards
references. ``run_all`` runs every detector and concatenates the results.

A finding is only raised when there is concrete evidence; well-formed captures
(e.g. the unaffected DHCPv6 exchange) yield no findings, so the verdict stays
clean. Pure stdlib.
"""

from .models import Finding

# Standards references, kept as constants so wording stays consistent.
_STD_XID = ['RFC 2131 section 4.1']
_STD_FOREIGN = ['RFC 2131 section 4.4.1']
_STD_CLIENTID = ['RFC 4361', 'O-RAN.WG4.MP section 6.2.4']
_STD_DUP = ['RFC 2131 section 4.1', 'RFC 2131 section 4.4.1']


def _fmt_ts(ts):
    """Render a capture timestamp as HH:MM:SS.mmm (UTC, stable across hosts)."""
    try:
        import time
        whole = int(ts)
        frac = ts - whole
        lt = time.gmtime(whole)
        return '%02d:%02d:%02d.%03d' % (lt.tm_hour, lt.tm_min, lt.tm_sec,
                                        int(round(frac * 1000)))
    except Exception:
        return str(ts)


def _evi(pkt, msg, ip=None):
    """Build one precise evidence line for a DHCPv4 packet/message pair."""
    parts = [
        'ts=%s' % _fmt_ts(pkt.ts),
        'eth_src=%s' % (pkt.eth_src or '-'),
        'chaddr=%s' % (msg.chaddr or '-'),
        'type=%s' % (msg.msg_type_name or '?'),
    ]
    show_ip = ip
    if show_ip is None:
        # Default to the most relevant IP for the message type.
        name = (msg.msg_type_name or '').upper()
        if name == 'OFFER' or name == 'ACK':
            show_ip = _clean_ip(msg.yiaddr)
        elif name == 'REQUEST':
            show_ip = msg.requested_ip or _clean_ip(msg.ciaddr)
    if show_ip:
        parts.append('ip=%s' % show_ip)
    return ' '.join(parts)


def _clean_ip(ip):
    if not ip or ip in ('0.0.0.0', '::'):
        return None
    return ip


def _v4_msgs(txn):
    """Yield (pkt, msg) pairs for the DHCPv4 messages in a transaction."""
    if txn.version != '4':
        return
    for pkt, msg in txn.packets:
        # decoded DHCPv4 messages expose chaddr + msg_type_name
        if getattr(msg, 'chaddr', None) is not None:
            yield pkt, msg


def _last3(mac):
    """Return the last 3 octets of a MAC-like string for loose comparison."""
    if not mac:
        return ''
    cleaned = mac.replace('-', ':').lower()
    octs = cleaned.split(':')
    return ':'.join(octs[-3:]) if len(octs) >= 3 else cleaned


# --------------------------------------------------------------------------- #
# Detector 1: shared transaction id across distinct units.
# --------------------------------------------------------------------------- #
def detect_shared_xid(transactions, packets=None):
    findings = []
    for txn in transactions:
        if txn.version != '4':
            continue
        chaddrs = []
        for _pkt, msg in _v4_msgs(txn):
            if msg.chaddr and msg.chaddr not in chaddrs:
                chaddrs.append(msg.chaddr)
        if len(chaddrs) < 2:
            continue
        evidence = [_evi(pkt, msg) for pkt, msg in _v4_msgs(txn)]
        findings.append(Finding(
            id='SHARED_XID',
            title='Shared DHCPv4 transaction-id across multiple units',
            severity='HIGH',
            category='dhcpv4-xid-collision',
            description=(
                'DHCPv4 transaction-id %s is shared by %d distinct client '
                'hardware addresses (%s). RFC 2131 requires the xid to be a '
                'value chosen by the client to associate replies with its own '
                'request; a shared xid lets each unit react to broadcast '
                'OFFERs intended for others.'
                % (hex(txn.xid), len(chaddrs), ', '.join(chaddrs))
            ),
            evidence=evidence,
            standards=list(_STD_XID),
            recommendation=(
                'Generate the DHCPv4 xid per unit from a cryptographically '
                'random source seeded with the unit MAC (e.g. CSPRNG XOR MAC '
                'bytes) so that no two O-RUs on the same L2 segment collide.'
            ),
        ))
    return findings


# --------------------------------------------------------------------------- #
# Detector 2: a unit reacting to an OFFER that was not addressed to it.
# --------------------------------------------------------------------------- #
def detect_foreign_offer_reaction(transactions, packets=None):
    findings = []
    for txn in transactions:
        if txn.version != '4':
            continue
        msgs = list(_v4_msgs(txn))
        if not msgs:
            continue

        # The chaddr of the unit that originated this transaction (DISCOVER).
        discover_chaddr = None
        for _pkt, msg in msgs:
            if (msg.msg_type_name or '').upper() == 'DISCOVER':
                discover_chaddr = msg.chaddr
                break

        # Map offered IP -> set of chaddrs the server OFFERed it to.
        offered_to = {}
        for _pkt, msg in msgs:
            if (msg.msg_type_name or '').upper() == 'OFFER':
                ip = _clean_ip(msg.yiaddr)
                if ip:
                    offered_to.setdefault(ip, [])
                    if msg.chaddr not in offered_to[ip]:
                        offered_to[ip].append(msg.chaddr)

        evidence = []
        bad_chaddrs = []
        for pkt, msg in msgs:
            if (msg.msg_type_name or '').upper() != 'REQUEST':
                continue
            req_ip = msg.requested_ip or _clean_ip(msg.ciaddr)
            reason = None
            # (a) REQUEST chaddr differs from the unit that DISCOVERed.
            if discover_chaddr and msg.chaddr and msg.chaddr != discover_chaddr:
                reason = ('REQUEST from %s but DISCOVER was sent by %s'
                          % (msg.chaddr, discover_chaddr))
            # (b) REQUEST for an IP OFFERed to a *different* chaddr.
            elif req_ip and req_ip in offered_to and \
                    msg.chaddr not in offered_to[req_ip]:
                reason = ('REQUEST for %s which was OFFERed to %s'
                          % (req_ip, ', '.join(offered_to[req_ip])))
            if reason:
                evidence.append(_evi(pkt, msg, req_ip) + '  <- ' + reason)
                if msg.chaddr not in bad_chaddrs:
                    bad_chaddrs.append(msg.chaddr)

        if evidence:
            findings.append(Finding(
                id='FOREIGN_OFFER_REACTION',
                title='Unit reacted to a DHCPv4 OFFER addressed to another unit',
                severity='HIGH',
                category='dhcpv4-offer-hijack',
                description=(
                    'In transaction %s, %d unit(s) sent a REQUEST for an '
                    'address that the server OFFERed to a different hardware '
                    'address (or did not originate the DISCOVER). RFC 2131 '
                    'section 4.4.1 requires a client to verify that an OFFER '
                    'is addressed to it (matching chaddr) before requesting it.'
                    % (hex(txn.xid), len(bad_chaddrs))
                ),
                evidence=evidence,
                standards=list(_STD_FOREIGN),
                recommendation=(
                    'Before sending a DHCPREQUEST, validate that the OFFER\'s '
                    'chaddr (and xid) match this unit; silently discard OFFERs '
                    'whose chaddr is not the local MAC.'
                ),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Detector 3: missing option 61 client identifier.
# --------------------------------------------------------------------------- #
def detect_missing_client_id(transactions, packets=None):
    # Group by chaddr so we emit one finding per offending unit. Option 61 is a
    # client identifier, so only client-originated messages (BOOTREQUEST /
    # DISCOVER, REQUEST, DECLINE, RELEASE, INFORM) are expected to carry it;
    # server replies (OFFER/ACK/NAK) legitimately omit it and must not be
    # flagged.
    _CLIENT_TYPES = {'DISCOVER', 'REQUEST', 'DECLINE', 'RELEASE', 'INFORM'}
    missing = {}  # chaddr -> list[(pkt,msg)]
    for txn in transactions:
        if txn.version != '4':
            continue
        for pkt, msg in _v4_msgs(txn):
            name = (msg.msg_type_name or '').upper()
            is_client = (msg.op == 1) or (name in _CLIENT_TYPES)
            if not is_client:
                continue
            if msg.client_id is None:
                missing.setdefault(msg.chaddr or '-', []).append((pkt, msg))

    findings = []
    for chaddr in missing:
        items = missing[chaddr]
        evidence = [_evi(pkt, msg) for pkt, msg in items]
        findings.append(Finding(
            id='MISSING_CLIENT_ID',
            title='DHCPv4 messages omit option 61 (client identifier)',
            severity='HIGH',
            category='dhcpv4-missing-client-id',
            description=(
                'Unit %s sent %d DHCPv4 message(s) with no option 61 '
                'client-identifier. Without a stable client-id the server '
                'can only key on chaddr/xid, which (combined with the shared '
                'xid defect) allows lease confusion between units.'
                % (chaddr, len(items))
            ),
            evidence=evidence,
            standards=list(_STD_CLIENTID),
            recommendation=(
                'Include a stable DHCPv4 option 61 client identifier on every '
                'message (e.g. type 0xff IAID+DUID per RFC 4361, or a value '
                'derived from the O-RU serial / MAC per O-RAN.WG4.MP 6.2.4).'
            ),
        ))
    return findings


# --------------------------------------------------------------------------- #
# Detector 4: Ethernet source MAC does not match BOOTP chaddr.
# --------------------------------------------------------------------------- #
def detect_chaddr_ethsrc_mismatch(transactions, packets=None):
    findings = []
    evidence = []
    pairs = []
    for txn in transactions:
        if txn.version != '4':
            continue
        for pkt, msg in _v4_msgs(txn):
            eth = (pkt.eth_src or '').lower()
            cha = (msg.chaddr or '').lower()
            if not eth or not cha:
                continue
            # Server-originated frames (OFFER/ACK/NAK) legitimately carry the
            # server MAC as eth_src while chaddr echoes the client; only flag
            # client-originated messages.
            name = (msg.msg_type_name or '').upper()
            if name in ('OFFER', 'ACK', 'NAK'):
                continue
            if eth != cha and _last3(eth) != _last3(cha):
                evidence.append(
                    _evi(pkt, msg) + '  <- eth_src %s != chaddr %s'
                    % (pkt.eth_src, msg.chaddr))
                pairs.append((pkt.eth_src, msg.chaddr))
    if evidence:
        findings.append(Finding(
            id='CHADDR_ETHSRC_MISMATCH',
            title='DHCPv4 frame Ethernet source MAC differs from BOOTP chaddr',
            severity='MEDIUM',
            category='dhcpv4-chaddr-mismatch',
            description=(
                'One or more client-originated DHCPv4 frames carry an Ethernet '
                'source address that does not match the BOOTP chaddr field. '
                'This indicates spoofing or relaying that can mask which unit '
                'actually transmitted the packet.'
            ),
            evidence=evidence,
            standards=list(_STD_FOREIGN),
            recommendation=(
                'Ensure the DHCPv4 chaddr equals the interface MAC used to '
                'transmit the frame; reject or log frames where they differ.'
            ),
        ))
    return findings


# --------------------------------------------------------------------------- #
# Detector 5: duplicate grants / IP theft.
# --------------------------------------------------------------------------- #
def detect_duplicate_grants(transactions, packets=None):
    """Same chaddr winning >1 distinct IP, or same IP requested by >1 chaddr.

    Both checks are scoped to the documented O-RU defect: contention within a
    *single shared-xid transaction*. A "shared-xid" transaction is one in which
    two or more distinct client hardware addresses appear under the same xid --
    exactly the collision the bug report describes. Aggregating across
    independent transactions (different xids) would mistake normal sequential
    lease churn -- one IP reassigned to a new MAC later, or one MAC renewing
    onto a different address -- for IP theft / duplicate leases, so we never do
    that here.

    A "winning" REQUEST is one followed by an ACK in the same transaction.
    """
    findings = []

    # Grants won inside shared-xid transactions, used only to detect a single
    # MAC that wins multiple addresses via the collision. Keyed by chaddr.
    shared_chaddr_to_ips = {}   # chaddr -> [ips it won via shared-xid contention]
    shared_chaddr_evi = {}      # chaddr -> evidence lines

    for txn in transactions:
        if txn.version != '4':
            continue
        msgs = list(_v4_msgs(txn))

        # Distinct client hardware addresses appearing under this single xid.
        # >=2 means the xid is shared between units (the documented defect).
        txn_chaddrs = []
        for _pkt, msg in msgs:
            if msg.chaddr and msg.chaddr not in txn_chaddrs:
                txn_chaddrs.append(msg.chaddr)
        is_shared_xid = len(txn_chaddrs) >= 2

        # Determine which IPs were ACKed and to whom, within THIS transaction.
        acked = {}  # ip -> chaddr (granted)
        for _pkt, msg in msgs:
            if (msg.msg_type_name or '').upper() == 'ACK':
                ip = _clean_ip(msg.yiaddr)
                if ip:
                    acked[ip] = msg.chaddr

        # Per-transaction contention: which chaddrs requested each IP, scoped to
        # this single xid context only (reset every transaction).
        ip_to_chaddrs = {}   # ip -> [chaddrs that requested it in this txn]
        ip_evi = {}          # ip -> evidence lines for this txn

        for pkt, msg in msgs:
            if (msg.msg_type_name or '').upper() != 'REQUEST':
                continue
            ip = msg.requested_ip or _clean_ip(msg.ciaddr)
            if not ip:
                continue
            # Record every requester of this IP within this transaction.
            ip_to_chaddrs.setdefault(ip, [])
            if msg.chaddr not in ip_to_chaddrs[ip]:
                ip_to_chaddrs[ip].append(msg.chaddr)
            ip_evi.setdefault(ip, []).append(_evi(pkt, msg, ip))

            # A grant won via shared-xid contention: this chaddr's REQUEST was
            # ACKed for this IP inside a transaction whose xid is shared.
            if is_shared_xid and acked.get(ip) == msg.chaddr:
                shared_chaddr_to_ips.setdefault(msg.chaddr, [])
                if ip not in shared_chaddr_to_ips[msg.chaddr]:
                    shared_chaddr_to_ips[msg.chaddr].append(ip)
                shared_chaddr_evi.setdefault(msg.chaddr, []).append(
                    _evi(pkt, msg, ip)
                    + ('  <- granted (ACK) under shared xid %s' % hex(txn.xid)))

        # (b) one IP requested by multiple chaddrs WITHIN this single xid
        # (IP theft / contention). Only meaningful when the xid is shared.
        if not is_shared_xid:
            continue
        for ip in ip_to_chaddrs:
            chaddrs = ip_to_chaddrs[ip]
            if len(chaddrs) >= 2:
                findings.append(Finding(
                    id='DUPLICATE_GRANT_IP',
                    title='Single IP contested by multiple units (IP theft)',
                    severity='HIGH',
                    category='dhcpv4-ip-theft',
                    description=(
                        'IP address %s was requested by %d distinct hardware '
                        'addresses (%s) within the same DHCPv4 transaction '
                        '(shared xid %s), indicating multiple O-RUs racing for '
                        'one offered address.'
                        % (ip, len(chaddrs), ', '.join(chaddrs), hex(txn.xid))
                    ),
                    evidence=list(ip_evi.get(ip, [])),
                    standards=list(_STD_DUP),
                    recommendation=(
                        'Eliminate the shared-xid / foreign-OFFER behaviour so '
                        'only the addressed unit requests an offered IP.'
                    ),
                ))

    # (a) one chaddr granted multiple distinct IPs via shared-xid contention
    # (duplicate lease on a unit that won addresses it should not have).
    for chaddr in shared_chaddr_to_ips:
        ips = shared_chaddr_to_ips[chaddr]
        if len(ips) >= 2:
            findings.append(Finding(
                id='DUPLICATE_GRANT_MAC',
                title='Single unit granted multiple DHCPv4 leases',
                severity='HIGH',
                category='dhcpv4-duplicate-lease',
                description=(
                    'Hardware address %s was granted %d distinct IP addresses '
                    '(%s) by winning REQUESTs across shared-xid transactions. A '
                    'single O-RU holding multiple leases via xid collision '
                    'starves other units of addresses.'
                    % (chaddr, len(ips), ', '.join(ips))
                ),
                evidence=list(shared_chaddr_evi.get(chaddr, [])),
                standards=list(_STD_DUP),
                recommendation=(
                    'Fix the xid/chaddr validation so a unit only completes one '
                    'lease for itself; release extra leases held by one MAC.'
                ),
            ))

    return findings


# --------------------------------------------------------------------------- #
# Aggregator.
# --------------------------------------------------------------------------- #
_ALL_DETECTORS = (
    detect_shared_xid,
    detect_foreign_offer_reaction,
    detect_missing_client_id,
    detect_chaddr_ethsrc_mismatch,
    detect_duplicate_grants,
)


def run_all(transactions, packets):
    """Run every detector and return the concatenated findings (may be empty)."""
    findings = []
    for det in _ALL_DETECTORS:
        try:
            result = det(transactions, packets)
        except Exception:
            result = []
        if result:
            findings.extend(result)
    return findings
