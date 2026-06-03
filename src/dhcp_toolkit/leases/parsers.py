"""DHCP lease-file parsers (ISC + Kea, DHCPv4 + DHCPv6).

Ported from ``dhcp_lease_list_v1.3.0.py``; every parser returns ``list[Lease]``.

All bugfix logic noted in the original changelog (1.0 -> 1.3) is preserved:

* DUID MAC extraction for DUID-LLT (type 1), DUID-LL (type 3) and DUID-EN
  (type 2 ASCII scan), including the 4-byte IAID prefix on the ``ia-na`` key
  (changelog 1.1.0 / 1.1.1 / 1.2.0 / 1.2.1).
* ISC and Kea journal-aware dedup: keep the most recent *active* lease per IP
  (active always beats non-active; for equal states the later expiry wins).

Pure stdlib only.
"""

import re
import csv
from datetime import datetime
from pathlib import Path

from .models import Lease

# Kea lease state codes
KEA_STATES = {
    "0": "active",
    "1": "declined",
    "2": "expired",
    "3": "released",
}

# ANSI colors (used only in WARN/ERROR messages, preserved from original)
RESET = "\033[0m"
YELLOW = "\033[33m"
RED = "\033[31m"


# ---------------------------------------------------------------------------
# ISC DHCP parsers
# ---------------------------------------------------------------------------

def parse_isc_v4(path):
    """Parse an ISC DHCPv4 lease file (``dhcpd.leases``) -> list[Lease]."""
    leases = {}
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] DHCPv4 lease file not found: {path}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {path} (try sudo){RESET}")
        return []

    blocks = re.findall(r'lease\s+([\d.]+)\s*\{([^}]+)\}', text, re.DOTALL)
    for ip, block in blocks:
        m = re.search(r'binding state\s+(\w+);', block)
        state = m.group(1) if m else "unknown"
        m = re.search(r'hardware ethernet\s+([\w:]+);', block)
        mac = m.group(1) if m else "-"
        m = re.search(r'client-hostname\s+"([^"]+)";', block)
        hostname = m.group(1) if m else "-"
        m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+);', block)
        expires = m.group(1) if m else "-"
        m = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+);', block)
        starts = m.group(1) if m else "-"
        m = re.search(r'option vendor-class-identifier\s+"([^"]+)";', block)
        vendor_class = m.group(1) if m else "-"

        lease = Lease(
            ip=ip, version="4", server="isc", state=state,
            mac=mac, hostname=hostname, expires=expires, starts=starts,
            vendor_class=vendor_class,
        )

        if ip not in leases:
            leases[ip] = lease
        else:
            existing = leases[ip]
            if lease.state == "active" and existing.state != "active":
                leases[ip] = lease
            elif lease.state == existing.state:
                if lease.expires > existing.expires:
                    leases[ip] = lease

    return list(leases.values())


def extract_mac_from_duid(duid_raw):
    """Extract a MAC address from a DHCPv6 DUID (DUID-LLT, DUID-LL, DUID-EN).

    ``duid_raw`` is the raw key string captured from the ``ia-na "..."`` token,
    which has a 4-byte IAID prepended before the DUID itself.
    """
    try:
        raw = duid_raw.encode('raw_unicode_escape').decode('unicode_escape').encode('latin-1')
    except Exception:
        return "-"

    IAID_LEN = 4
    if len(raw) < IAID_LEN + 2:
        return "-"

    duid = raw[IAID_LEN:]
    duid_type = (duid[0] << 8 | duid[1])

    if duid_type == 1 and len(duid) >= 14:
        mac_bytes = duid[8:14]
        return ":".join(f"{b:02x}" for b in mac_bytes)

    elif duid_type == 3 and len(duid) >= 10:
        mac_bytes = duid[4:10]
        return ":".join(f"{b:02x}" for b in mac_bytes)

    elif duid_type == 2 and len(duid) > 4:
        for start in range(4, len(duid)):
            try:
                chunk = duid[start:].decode('ascii')
                m = re.search(r'([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})', chunk)
                if m:
                    return m.group(1).lower()
                m = re.search(r'^(:[0-9a-fA-F]{2}){5}', chunk)
                if m and start > 0:
                    first_byte = f"{duid[start-1]:02x}"
                    rest = chunk[:m.end()]
                    mac = first_byte + rest
                    if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                        return mac.lower()
            except Exception:
                continue

    return "-"


def parse_isc_v6(path):
    """Parse an ISC DHCPv6 lease file (``dhcpd6.leases``) -> list[Lease]."""
    leases = {}
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] DHCPv6 lease file not found: {path}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {path} (try sudo){RESET}")
        return []

    ia_blocks = re.findall(r'ia-na\s+"((?:[^"\\]|\\.)*)"\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
                           text, re.DOTALL)

    for duid_raw, ia_block in ia_blocks:
        mac = extract_mac_from_duid(duid_raw)

        addr_match = re.search(r'iaaddr\s+([\w:]+)\s*\{([^}]+)\}', ia_block, re.DOTALL)
        if not addr_match:
            continue
        ip = addr_match.group(1)
        addr_block = addr_match.group(2)

        m = re.search(r'binding state\s+(\w+);', addr_block)
        state = m.group(1) if m else "unknown"
        m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+);', addr_block)
        expires = m.group(1) if m else "-"
        m = re.search(r'cltt\s+\d+\s+([\d/]+\s+[\d:]+);', ia_block)
        starts = m.group(1) if m else "-"

        lease = Lease(
            ip=ip, version="6", server="isc", state=state,
            mac=mac, hostname="-", expires=expires, starts=starts,
            vendor_class="-", duid=duid_raw,
        )

        if ip not in leases:
            leases[ip] = lease
        else:
            existing = leases[ip]
            if lease.state == "active" and existing.state != "active":
                leases[ip] = lease
            elif lease.state == existing.state:
                if lease.expires > existing.expires:
                    leases[ip] = lease

    return list(leases.values())


# ---------------------------------------------------------------------------
# Kea DHCP CSV parsers
# ---------------------------------------------------------------------------

def epoch_to_datetime(epoch_str):
    """Convert a Unix epoch string to ``'YYYY/MM/DD HH:MM:SS'`` (or '-')."""
    try:
        ts = int(epoch_str)
        return datetime.fromtimestamp(ts).strftime("%Y/%m/%d %H:%M:%S")
    except Exception:
        return "-"


def parse_kea_v4(path):
    """Parse a Kea DHCPv4 CSV lease file (``kea-leases4.csv``) -> list[Lease].

    Columns: address, hwaddr, client_id, valid_lifetime, expire, subnet_id,
    fqdn_fwd, fqdn_rev, hostname, state, user_context, pool_id.

    State: 0=active, 1=declined, 2=expired-reclaimed, 3=released.

    Kea appends new entries rather than updating in place (journal style), so we
    keep only the most recent active entry per IP address.
    """
    leases = {}
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] Kea DHCPv4 lease file not found: {path}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {path} (try sudo){RESET}")
        return []

    reader = csv.DictReader(text.splitlines())
    for row in reader:
        try:
            ip = row.get("address", "").strip()
            if not ip:
                continue

            state_code = row.get("state", "0").strip()
            state = KEA_STATES.get(state_code, f"state-{state_code}")
            mac = row.get("hwaddr", "-").strip() or "-"
            hostname = row.get("hostname", "-").strip() or "-"
            expire = epoch_to_datetime(row.get("expire", "0").strip())
            valid_lft = row.get("valid_lifetime", "-").strip()

            lease = Lease(
                ip=ip, version="4", server="kea", state=state,
                mac=mac, hostname=hostname, expires=expire, starts="-",
                vendor_class="-", valid_lft=valid_lft,
            )

            # Keep most recent entry per IP (last row in CSV wins for same state)
            if ip not in leases:
                leases[ip] = lease
            else:
                existing = leases[ip]
                # Active always beats non-active
                if state == "active" and existing.state != "active":
                    leases[ip] = lease
                # Same state: keep later expiry
                elif state == existing.state:
                    if expire > existing.expires:
                        leases[ip] = lease

        except Exception:
            continue

    return list(leases.values())


def parse_kea_v6(path):
    """Parse a Kea DHCPv6 CSV lease file (``kea-leases6.csv``) -> list[Lease].

    Columns: address, duid, valid_lifetime, expire, subnet_id, pref_lifetime,
    lease_type, iaid, prefix_len, fqdn_fwd, fqdn_rev, hostname, hwaddr, state,
    user_context, hwtype, hwaddr_source, pool_id.

    State: 0=active, 1=declined, 2=expired-reclaimed, 3=released.
    lease_type: 0=IA_NA (address), 2=IA_PD (prefix delegation, skipped).
    """
    leases = {}
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] Kea DHCPv6 lease file not found: {path}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {path} (try sudo){RESET}")
        return []

    reader = csv.DictReader(text.splitlines())
    for row in reader:
        try:
            ip = row.get("address", "").strip()
            if not ip:
                continue

            # Skip prefix delegation entries (lease_type=2); show addresses only.
            lease_type = row.get("lease_type", "0").strip()
            if lease_type == "2":
                continue

            state_code = row.get("state", "0").strip()
            state = KEA_STATES.get(state_code, f"state-{state_code}")

            # Kea v6 stores hwaddr directly as a column (may be empty)
            mac = row.get("hwaddr", "-").strip() or "-"

            hostname = row.get("hostname", "-").strip() or "-"
            expire = epoch_to_datetime(row.get("expire", "0").strip())
            valid_lft = row.get("valid_lifetime", "-").strip()
            duid = row.get("duid", "-").strip() or "-"

            lease = Lease(
                ip=ip, version="6", server="kea", state=state,
                mac=mac, hostname=hostname, expires=expire, starts="-",
                vendor_class="-", duid=duid, valid_lft=valid_lft,
            )

            if ip not in leases:
                leases[ip] = lease
            else:
                existing = leases[ip]
                if state == "active" and existing.state != "active":
                    leases[ip] = lease
                elif state == existing.state:
                    if expire > existing.expires:
                        leases[ip] = lease

        except Exception:
            continue

    return list(leases.values())
