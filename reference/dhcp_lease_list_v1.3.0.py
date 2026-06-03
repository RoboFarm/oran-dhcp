#!/usr/bin/env python3
"""
dhcp_lease_list.py - Unified DHCP lease viewer for ISC and Kea DHCP
Displays active leases from ISC dhcpd.leases / dhcpd6.leases
                   or Kea kea-leases4.csv / kea-leases6.csv
"""

__version__ = "1.3.0"
# Changelog:
# 1.0.0 - Initial release, IPv4 + IPv6 ISC lease parsing
# 1.1.0 - Fixed DHCPv6 binary DUID parsing, added MAC extraction from DUID-LLT/LL,
#          fixed datetime deprecation warning
# 1.1.1 - Fixed MAC extraction offset: ia-na key has 4-byte IAID prepended before DUID
# 1.2.0 - Added DUID-EN (type 2) support with ASCII MAC extraction
#          Fixed IPv4 dedup logic to always keep most recent active lease
# 1.2.1 - Fixed DUID-EN MAC extraction: handle 2-byte enterprise number and partial
#          MAC string (missing first octet) by scanning variable offsets
# 1.3.0 - Added Kea DHCP CSV lease file support (kea-leases4.csv, kea-leases6.csv)
#          Added --server {isc,kea} switch to select DHCP server type

import re
import csv
import argparse
from datetime import datetime
from pathlib import Path

# Default lease file locations — ISC
DEFAULT_ISC_V4 = "/var/lib/dhcp/dhcpd.leases"
DEFAULT_ISC_V6 = "/var/lib/dhcp/dhcpd6.leases"

# Default lease file locations — Kea
DEFAULT_KEA_V4 = "/var/lib/kea/kea-leases4.csv"
DEFAULT_KEA_V6 = "/var/lib/kea/kea-leases6.csv"

# Kea lease state codes
KEA_STATES = {
    "0": "active",
    "1": "declined",
    "2": "expired",
    "3": "released",
}

# ANSI colors
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
DIM    = "\033[2m"


# ---------------------------------------------------------------------------
# ISC DHCP parsers
# ---------------------------------------------------------------------------

def parse_v4_leases(filepath):
    """Parse ISC DHCPv4 lease file."""
    leases = {}
    try:
        text = Path(filepath).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] DHCPv4 lease file not found: {filepath}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {filepath} (try sudo){RESET}")
        return []

    blocks = re.findall(r'lease\s+([\d.]+)\s*\{([^}]+)\}', text, re.DOTALL)
    for ip, block in blocks:
        lease = {"ip": ip, "version": "4", "server": "isc"}
        m = re.search(r'binding state\s+(\w+);', block)
        lease["state"] = m.group(1) if m else "unknown"
        m = re.search(r'hardware ethernet\s+([\w:]+);', block)
        lease["mac"] = m.group(1) if m else "-"
        m = re.search(r'client-hostname\s+"([^"]+)";', block)
        lease["hostname"] = m.group(1) if m else "-"
        m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+);', block)
        lease["expires"] = m.group(1) if m else "-"
        m = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+);', block)
        lease["starts"] = m.group(1) if m else "-"
        m = re.search(r'option vendor-class-identifier\s+"([^"]+)";', block)
        lease["vendor_class"] = m.group(1) if m else "-"

        if ip not in leases:
            leases[ip] = lease
        else:
            existing = leases[ip]
            if lease["state"] == "active" and existing["state"] != "active":
                leases[ip] = lease
            elif lease["state"] == existing["state"]:
                if lease["expires"] > existing["expires"]:
                    leases[ip] = lease

    return list(leases.values())


def extract_mac_from_duid(duid_raw):
    """Extract MAC from DHCPv6 DUID (DUID-LLT, DUID-LL, DUID-EN)."""
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


def parse_v6_leases(filepath):
    """Parse ISC DHCPv6 lease file."""
    leases = {}
    try:
        text = Path(filepath).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] DHCPv6 lease file not found: {filepath}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {filepath} (try sudo){RESET}")
        return []

    ia_blocks = re.findall(r'ia-na\s+"((?:[^"\\]|\\.)*)"\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
                           text, re.DOTALL)

    for duid_raw, ia_block in ia_blocks:
        lease = {"version": "6", "server": "isc"}
        lease["mac"] = extract_mac_from_duid(duid_raw)

        addr_match = re.search(r'iaaddr\s+([\w:]+)\s*\{([^}]+)\}', ia_block, re.DOTALL)
        if not addr_match:
            continue
        ip = addr_match.group(1)
        addr_block = addr_match.group(2)

        lease["ip"] = ip
        m = re.search(r'binding state\s+(\w+);', addr_block)
        lease["state"] = m.group(1) if m else "unknown"
        m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+);', addr_block)
        lease["expires"] = m.group(1) if m else "-"
        m = re.search(r'cltt\s+\d+\s+([\d/]+\s+[\d:]+);', ia_block)
        lease["starts"] = m.group(1) if m else "-"
        lease["hostname"] = "-"
        lease["vendor_class"] = "-"

        if ip not in leases:
            leases[ip] = lease
        else:
            existing = leases[ip]
            if lease["state"] == "active" and existing["state"] != "active":
                leases[ip] = lease
            elif lease["state"] == existing["state"]:
                if lease["expires"] > existing["expires"]:
                    leases[ip] = lease

    return list(leases.values())


# ---------------------------------------------------------------------------
# Kea DHCP CSV parsers
# ---------------------------------------------------------------------------

def epoch_to_datetime(epoch_str):
    """Convert Unix epoch string to 'YYYY/MM/DD HH:MM:SS' format."""
    try:
        ts = int(epoch_str)
        return datetime.fromtimestamp(ts).strftime("%Y/%m/%d %H:%M:%S")
    except Exception:
        return "-"


def parse_kea_v4_leases(filepath):
    """
    Parse Kea DHCPv4 CSV lease file.

    Columns: address, hwaddr, client_id, valid_lifetime, expire,
             subnet_id, fqdn_fwd, fqdn_rev, hostname, state,
             user_context, pool_id

    State: 0=active, 1=declined, 2=expired-reclaimed, 3=released

    Kea appends new entries rather than updating in place (journal style),
    so we keep only the most recent entry per IP address.
    """
    leases = {}
    try:
        text = Path(filepath).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] Kea DHCPv4 lease file not found: {filepath}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {filepath} (try sudo){RESET}")
        return []

    reader = csv.DictReader(text.splitlines())
    for row in reader:
        try:
            ip       = row.get("address", "").strip()
            if not ip:
                continue

            state_code = row.get("state", "0").strip()
            state      = KEA_STATES.get(state_code, f"state-{state_code}")
            mac        = row.get("hwaddr", "-").strip() or "-"
            hostname   = row.get("hostname", "-").strip() or "-"
            expire     = epoch_to_datetime(row.get("expire", "0").strip())
            valid_lft  = row.get("valid_lifetime", "-").strip()

            lease = {
                "ip":           ip,
                "version":      "4",
                "server":       "kea",
                "state":        state,
                "mac":          mac,
                "hostname":     hostname,
                "expires":      expire,
                "starts":       "-",
                "vendor_class": "-",
                "valid_lft":    valid_lft,
            }

            # Keep most recent entry per IP (last row in CSV wins for same state)
            if ip not in leases:
                leases[ip] = lease
            else:
                existing = leases[ip]
                # Active always beats non-active
                if state == "active" and existing["state"] != "active":
                    leases[ip] = lease
                # Same state: keep later expiry
                elif state == existing["state"]:
                    if expire > existing["expires"]:
                        leases[ip] = lease

        except Exception:
            continue

    return list(leases.values())


def parse_kea_v6_leases(filepath):
    """
    Parse Kea DHCPv6 CSV lease file.

    Columns: address, duid, valid_lifetime, expire, subnet_id,
             pref_lifetime, lease_type, iaid, prefix_len,
             fqdn_fwd, fqdn_rev, hostname, hwaddr, state,
             user_context, hwtype, hwaddr_source, pool_id

    State: 0=active, 1=declined, 2=expired-reclaimed, 3=released
    lease_type: 0=IA_NA (address), 2=IA_PD (prefix delegation)
    """
    leases = {}
    try:
        text = Path(filepath).read_text()
    except FileNotFoundError:
        print(f"{YELLOW}[WARN] Kea DHCPv6 lease file not found: {filepath}{RESET}")
        return []
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied: {filepath} (try sudo){RESET}")
        return []

    reader = csv.DictReader(text.splitlines())
    for row in reader:
        try:
            ip = row.get("address", "").strip()
            if not ip:
                continue

            # Skip prefix delegation entries (lease_type=2), show only addresses (type=0)
            lease_type = row.get("lease_type", "0").strip()
            if lease_type == "2":
                continue

            state_code = row.get("state", "0").strip()
            state      = KEA_STATES.get(state_code, f"state-{state_code}")

            # Kea v6 stores hwaddr directly as a column (may be empty)
            mac = row.get("hwaddr", "-").strip() or "-"

            hostname  = row.get("hostname", "-").strip() or "-"
            expire    = epoch_to_datetime(row.get("expire", "0").strip())
            valid_lft = row.get("valid_lifetime", "-").strip()
            duid      = row.get("duid", "-").strip() or "-"

            lease = {
                "ip":           ip,
                "version":      "6",
                "server":       "kea",
                "state":        state,
                "mac":          mac,
                "duid":         duid,
                "hostname":     hostname,
                "expires":      expire,
                "starts":       "-",
                "vendor_class": "-",
                "valid_lft":    valid_lft,
            }

            if ip not in leases:
                leases[ip] = lease
            else:
                existing = leases[ip]
                if state == "active" and existing["state"] != "active":
                    leases[ip] = lease
                elif state == existing["state"]:
                    if expire > existing["expires"]:
                        leases[ip] = lease

        except Exception:
            continue

    return list(leases.values())


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def is_expired(expires_str):
    """Return True if lease has already expired."""
    try:
        exp = datetime.strptime(expires_str, "%Y/%m/%d %H:%M:%S")
        return exp < datetime.now()
    except Exception:
        return False


def state_color(state, expires):
    """Return colored state string."""
    if state == "active" and not is_expired(expires):
        return f"{GREEN}{state}{RESET}"
    elif state in ("free", "released"):
        return f"{DIM}{state}{RESET}"
    else:
        return f"{YELLOW}{state}{RESET}"


def print_leases(leases, show_expired=False, filter_state=None):
    """Pretty-print lease table."""
    if not leases:
        return

    if not show_expired:
        leases = [l for l in leases
                  if not (l["state"] == "active" and is_expired(l["expires"]))]
    if filter_state:
        leases = [l for l in leases if l["state"] == filter_state]

    if not leases:
        print(f"  {DIM}No leases to display.{RESET}\n")
        return

    w_ip   = max(len(l["ip"]) for l in leases) + 2
    w_mac  = max(len(l.get("mac", "-")) for l in leases) + 2
    w_host = max(len(l.get("hostname", "-")) for l in leases) + 2
    w_exp  = 22
    w_vc   = max(len(l.get("vendor_class", "-")) for l in leases) + 2

    header = (f"{'IP Address':<{w_ip}} {'MAC / DUID':<{w_mac}} "
              f"{'Hostname':<{w_host}} {'State':<12} "
              f"{'Expires (UTC)':<{w_exp}} {'Vendor Class':<{w_vc}}")
    sep = "-" * len(header)

    print(f"{BOLD}{header}{RESET}")
    print(sep)

    for l in sorted(leases, key=lambda x: x["ip"]):
        ip       = l["ip"]
        mac      = l.get("mac", "-")
        hostname = l.get("hostname", "-")
        state    = l.get("state", "-")
        expires  = l.get("expires", "-")
        vc       = l.get("vendor_class", "-")
        colored_state = state_color(state, expires)

        print(f"{CYAN}{ip:<{w_ip}}{RESET} {mac:<{w_mac}} {hostname:<{w_host}} "
              f"{colored_state:<{12 + len(colored_state) - len(state)}} "
              f"{expires:<{w_exp}} {DIM}{vc}{RESET}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"Unified DHCP lease viewer for ISC and Kea DHCP  v{__version__}"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--server", choices=["isc", "kea"], default="isc",
                        help="DHCP server type: isc (default) or kea")
    parser.add_argument("--v4-lease", default=None,
                        help="Path to IPv4 lease file (auto-selected based on --server if omitted)")
    parser.add_argument("--v6-lease", default=None,
                        help="Path to IPv6 lease file (auto-selected based on --server if omitted)")
    parser.add_argument("--all", action="store_true",
                        help="Show all leases including expired and free")
    parser.add_argument("--state", choices=["active", "free", "expired", "declined", "released"],
                        help="Filter by binding state")
    parser.add_argument("--v4-only", action="store_true", help="Show IPv4 leases only")
    parser.add_argument("--v6-only", action="store_true", help="Show IPv6 leases only")
    args = parser.parse_args()

    # Auto-select default lease file paths based on server type
    if args.server == "kea":
        v4_file = args.v4_lease or DEFAULT_KEA_V4
        v6_file = args.v6_lease or DEFAULT_KEA_V6
        parse_v4 = parse_kea_v4_leases
        parse_v6 = parse_kea_v6_leases
        server_label = "Kea"
    else:
        v4_file = args.v4_lease or DEFAULT_ISC_V4
        v6_file = args.v6_lease or DEFAULT_ISC_V6
        parse_v4 = parse_v4_leases
        parse_v6 = parse_v6_leases
        server_label = "ISC"

    show_v4 = not args.v6_only
    show_v6 = not args.v4_only

    print(f"\n{BOLD}=== {server_label} DHCP Unified Lease List  v{__version__} ==={RESET}")
    print(f"{DIM}Active leases shown. Use --all to include expired/free.{RESET}\n")

    if show_v4:
        v4_leases = parse_v4(v4_file)
        active_v4 = sum(1 for l in v4_leases
                        if l["state"] == "active" and not is_expired(l["expires"]))
        print(f"{BOLD}{CYAN}[ DHCPv4 Leases ]{RESET}  "
              f"{DIM}file: {v4_file}  total: {len(v4_leases)}  active: {active_v4}{RESET}")
        print_leases(v4_leases, show_expired=args.all, filter_state=args.state)

    if show_v6:
        v6_leases = parse_v6(v6_file)
        active_v6 = sum(1 for l in v6_leases
                        if l["state"] == "active" and not is_expired(l["expires"]))
        print(f"{BOLD}{CYAN}[ DHCPv6 Leases ]{RESET}  "
              f"{DIM}file: {v6_file}  total: {len(v6_leases)}  active: {active_v6}{RESET}")
        print_leases(v6_leases, show_expired=args.all, filter_state=args.state)


if __name__ == "__main__":
    main()
