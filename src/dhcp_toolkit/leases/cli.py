"""``dhcp-lease-list`` command-line entry point.

Preserves the original argparse interface from ``dhcp_lease_list_v1.3.0.py``
(--server, --v4-lease, --v6-lease, --all, --state, --v4-only, --v6-only,
--version) and adds ``--conflicts``: after listing, run :func:`find_conflicts`
on the parsed leases and print a clearly labelled conflict section.  Returns
exit code 2 if any HIGH-severity conflict is found, else 0.

Pure stdlib only.
"""

import sys
import argparse

from .. import __version__
from .parsers import (
    parse_isc_v4, parse_isc_v6, parse_kea_v4, parse_kea_v6,
)
from .display import is_expired, print_leases
from .conflicts import find_conflicts

# Default lease file locations -- ISC
DEFAULT_ISC_V4 = "/var/lib/dhcp/dhcpd.leases"
DEFAULT_ISC_V6 = "/var/lib/dhcp/dhcpd6.leases"

# Default lease file locations -- Kea
DEFAULT_KEA_V4 = "/var/lib/kea/kea-leases4.csv"
DEFAULT_KEA_V6 = "/var/lib/kea/kea-leases6.csv"

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
RED = "\033[31m"
DIM = "\033[2m"


def _print_conflicts(conflicts, use_color=True):
    """Print a clearly labelled conflict section; return True if any HIGH."""
    c_reset = RESET if use_color else ""
    c_bold = BOLD if use_color else ""
    c_red = RED if use_color else ""
    c_dim = DIM if use_color else ""

    print(f"{c_bold}{c_red}[ Lease Conflicts ]{c_reset}")
    if not conflicts:
        print(f"  {c_dim}No conflicts detected.{c_reset}\n")
        return False

    for c in conflicts:
        print(f"  {c_red}{c_bold}[{c.severity}]{c_reset} "
              f"{c_bold}{c.kind}{c_reset}: {c.detail}")
    print()
    return any(c.severity == "HIGH" for c in conflicts)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dhcp-lease-list",
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
    parser.add_argument("--conflicts", action="store_true",
                        help="After listing, scan parsed leases for MAC/IP "
                             "conflicts (exit 2 if any HIGH conflict found)")
    args = parser.parse_args(argv)

    # Auto-select default lease file paths based on server type.
    if args.server == "kea":
        v4_file = args.v4_lease or DEFAULT_KEA_V4
        v6_file = args.v6_lease or DEFAULT_KEA_V6
        parse_v4 = parse_kea_v4
        parse_v6 = parse_kea_v6
        server_label = "Kea"
    else:
        v4_file = args.v4_lease or DEFAULT_ISC_V4
        v6_file = args.v6_lease or DEFAULT_ISC_V6
        parse_v4 = parse_isc_v4
        parse_v6 = parse_isc_v6
        server_label = "ISC"

    show_v4 = not args.v6_only
    show_v6 = not args.v4_only

    print(f"\n{BOLD}=== {server_label} DHCP Unified Lease List  v{__version__} ==={RESET}")
    print(f"{DIM}Active leases shown. Use --all to include expired/free.{RESET}\n")

    all_leases = []

    if show_v4:
        v4_leases = parse_v4(v4_file)
        all_leases.extend(v4_leases)
        active_v4 = sum(1 for l in v4_leases
                        if l.state == "active" and not is_expired(l.expires))
        print(f"{BOLD}{CYAN}[ DHCPv4 Leases ]{RESET}  "
              f"{DIM}file: {v4_file}  total: {len(v4_leases)}  active: {active_v4}{RESET}")
        print_leases(v4_leases, show_expired=args.all, filter_state=args.state)

    if show_v6:
        v6_leases = parse_v6(v6_file)
        all_leases.extend(v6_leases)
        active_v6 = sum(1 for l in v6_leases
                        if l.state == "active" and not is_expired(l.expires))
        print(f"{BOLD}{CYAN}[ DHCPv6 Leases ]{RESET}  "
              f"{DIM}file: {v6_file}  total: {len(v6_leases)}  active: {active_v6}{RESET}")
        print_leases(v6_leases, show_expired=args.all, filter_state=args.state)

    if args.conflicts:
        conflicts = find_conflicts(all_leases)
        has_high = _print_conflicts(conflicts)
        if has_high:
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
