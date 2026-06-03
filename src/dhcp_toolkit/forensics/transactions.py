"""Group decoded DHCP packets into per-transaction views.

DHCPv4 packets (UDP ports 67/68) are grouped by their transaction id (xid);
DHCPv6 packets (UDP ports 546/547) are grouped by their 24-bit transaction id.
Each resulting :class:`~dhcp_toolkit.forensics.models.Transaction` keeps its
member packets in capture (time) order together with the decoded message, and
carries convenience rollups (distinct chaddr, eth_src, offered / requested IPs)
that the detectors consume.

Pure stdlib; depends only on the contract APIs of ``forensics.pcap`` (for the
``CapturedPacket`` shape) and ``forensics.dhcp`` (for the decoders).
"""

from .models import Transaction
from .dhcp import decode_dhcpv4, decode_dhcpv6

# UDP ports that carry DHCP traffic.
DHCPV4_PORTS = (67, 68)
DHCPV6_PORTS = (546, 547)


def _append_unique(seq, value):
    """Append ``value`` to ``seq`` preserving first-seen order, skipping
    empties / duplicates."""
    if value is None:
        return
    if value == '' or value == '-':
        return
    if value not in seq:
        seq.append(value)


def build_transactions(packets):
    """Decode every DHCP packet in ``packets`` and group them into transactions.

    Args:
        packets: iterable of ``CapturedPacket`` (as produced by ``read_pcap``).

    Returns:
        list[Transaction]: DHCPv4 transactions keyed ``'v4:' + hex(xid)`` and
        DHCPv6 transactions keyed ``'v6:' + hex(transaction_id)``. Packets
        inside each transaction stay in capture order; transactions are ordered
        by the timestamp of their first packet.
    """
    # Preserve capture order; if timestamps are present sort stably by ts so
    # out-of-order capture records still yield a sensible timeline.
    ordered = sorted(enumerate(packets), key=lambda iv: (iv[1].ts, iv[0]))

    by_key = {}
    order = []  # keys in first-seen order

    for _idx, pkt in ordered:
        if pkt.l4 != 'udp':
            continue
        sp = pkt.src_port
        dp = pkt.dst_port

        if sp in DHCPV4_PORTS or dp in DHCPV4_PORTS:
            msg = decode_dhcpv4(pkt.payload)
            if msg is None:
                continue
            key = 'v4:' + hex(msg.xid)
            txn = by_key.get(key)
            if txn is None:
                txn = Transaction(key=key, version='4', xid=msg.xid)
                by_key[key] = txn
                order.append(key)
            _record_v4(txn, pkt, msg)

        elif sp in DHCPV6_PORTS or dp in DHCPV6_PORTS:
            msg = decode_dhcpv6(pkt.payload)
            if msg is None:
                continue
            key = 'v6:' + hex(msg.transaction_id)
            txn = by_key.get(key)
            if txn is None:
                txn = Transaction(key=key, version='6', xid=msg.transaction_id)
                by_key[key] = txn
                order.append(key)
            _record_v6(txn, pkt, msg)

    return [by_key[k] for k in order]


def _record_v4(txn, pkt, msg):
    """Attach a decoded DHCPv4 message to its transaction and update rollups."""
    txn.packets.append((pkt, msg))
    _append_unique(txn.macs, msg.chaddr)
    _append_unique(txn.eth_srcs, pkt.eth_src)

    name = (msg.msg_type_name or '').upper()

    # OFFER carries the granted address in yiaddr.
    if name == 'OFFER':
        _append_unique(txn.offered_ips, _norm_ip(msg.yiaddr))
    # REQUEST carries the desired address either in option 50 (requested_ip)
    # or, for renew/rebind, in ciaddr. Track both the offered side (the IP a
    # client is racing for) and the requested side.
    if name == 'REQUEST':
        req = msg.requested_ip or _norm_ip(msg.ciaddr)
        _append_unique(txn.requested_ips, req)
        _append_unique(txn.offered_ips, req)
    # ACK confirms a lease in yiaddr; record it as an offered/granted IP too.
    if name == 'ACK':
        _append_unique(txn.offered_ips, _norm_ip(msg.yiaddr))


def _record_v6(txn, pkt, msg):
    """Attach a decoded DHCPv6 message to its transaction and update rollups."""
    txn.packets.append((pkt, msg))
    _append_unique(txn.eth_srcs, pkt.eth_src)
    # For v6, identity lives in the DUID; expose its hex in macs for symmetry.
    if msg.client_duid:
        _append_unique(txn.macs, msg.client_duid.hex())
    for addr in (msg.addresses or []):
        _append_unique(txn.offered_ips, addr)


def _norm_ip(ip):
    """Treat the all-zeros address (and blanks) as 'no IP'."""
    if not ip or ip in ('0.0.0.0', '::'):
        return None
    return ip
