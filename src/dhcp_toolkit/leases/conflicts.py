"""Lease conflict detection.

Inspects parsed leases for two HIGH-severity anomalies that are the lease-table
fingerprint of the O-RU shared-xid / IP-theft defect:

(a) ``mac_multiple_active_ips`` -- one MAC holding more than one distinct ACTIVE
    IP of the *same* address family (one O-RU has hoarded several leases).
(b) ``ip_multiple_active_macs`` -- one IP claimed as ACTIVE by more than one
    distinct MAC (two units fighting over the same address).

Only ACTIVE, non-expired leases are considered.  Placeholder/empty MACs
('-', '') are ignored.  Output is deterministically sorted for stable display
and testing.

Pure stdlib only.
"""

from .models import Conflict
from .display import is_expired


def _is_active(lease):
    """True only for genuinely active (not expired) leases."""
    return lease.state == "active" and not is_expired(lease.expires)


def _valid_mac(mac):
    """True if ``mac`` is a real address rather than a placeholder."""
    return bool(mac) and mac != "-"


def find_conflicts(leases):
    """Return a list of :class:`Conflict` for the given ``leases``.

    Detects MACs holding multiple distinct active IPs of one family and IPs
    held by multiple distinct active MACs.  The result is sorted for stable
    output.
    """
    conflicts = []

    # (a) one MAC -> many distinct active IPs of the same family.
    # Group by (mac, version) so an IPv4 and an IPv6 lease for the same unit
    # do not spuriously trip the detector.
    mac_ips = {}
    for l in leases:
        if not _is_active(l) or not _valid_mac(l.mac):
            continue
        key = (l.mac, l.version)
        mac_ips.setdefault(key, set()).add(l.ip)

    for (mac, version), ips in mac_ips.items():
        if len(ips) > 1:
            sorted_ips = sorted(ips)
            fam = "IPv4" if version == "4" else "IPv6" if version == "6" else f"v{version}"
            detail = (f"MAC {mac} holds {len(sorted_ips)} distinct active "
                      f"{fam} addresses: {', '.join(sorted_ips)}")
            conflicts.append(Conflict(
                kind="mac_multiple_active_ips",
                severity="HIGH",
                detail=detail,
                ips=sorted_ips,
                macs=[mac],
            ))

    # (b) one IP -> many distinct active MACs.
    ip_macs = {}
    for l in leases:
        if not _is_active(l) or not _valid_mac(l.mac):
            continue
        ip_macs.setdefault(l.ip, set()).add(l.mac)

    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            sorted_macs = sorted(macs)
            detail = (f"IP {ip} is actively claimed by {len(sorted_macs)} "
                      f"distinct MACs: {', '.join(sorted_macs)}")
            conflicts.append(Conflict(
                kind="ip_multiple_active_macs",
                severity="HIGH",
                detail=detail,
                ips=[ip],
                macs=sorted_macs,
            ))

    # Stable, deterministic ordering: by kind, then primary key, then detail.
    conflicts.sort(key=lambda c: (
        c.kind,
        c.macs[0] if c.kind == "mac_multiple_active_ips" and c.macs else (c.ips[0] if c.ips else ""),
        c.detail,
    ))
    return conflicts
