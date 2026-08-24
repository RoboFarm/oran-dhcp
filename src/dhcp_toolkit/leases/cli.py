"""``dhcp-lease-list`` command-line entry point.

Preserves the original argparse interface from ``dhcp_lease_list_v1.3.0.py``
(--server, --v4-lease, --v6-lease, --all, --state, --v4-only, --v6-only,
--version) and adds ``--conflicts``: after listing, run :func:`find_conflicts`
on the parsed leases and print a clearly labelled conflict section.  Returns
exit code 2 if any HIGH-severity conflict is found, else 0.

``--server`` gained ``auto`` (now the default) and ``both``.  ``auto`` looks at
what is actually installed rather than assuming ISC: an explicitly named lease
file is identified by sniffing its format, and otherwise the Kea and ISC config
and lease paths are probed.  A host running only Kea therefore gets its leases
from a bare ``dhcp-lease-list``, and a host running both DHCP servers gets a
section for each.

Kea lease-file locations come from ``lease-database.name`` in the Kea config
rather than a hardcoded path, and a non-memfile lease backend is reported as
such instead of showing an empty table.

Pure stdlib only.
"""

import os
import sys
import argparse

from .. import __version__
from .parsers import (
    parse_isc_v4, parse_isc_v6, parse_kea_v4, parse_kea_v6, kea_lease_files,
)
from .display import is_expired, print_leases
from .conflicts import find_conflicts
from .kea_config import (
    discover_lease_source, find_config, DEFAULT_CONFIG_DIRS,
)

# Default lease file locations -- ISC
DEFAULT_ISC_V4 = "/var/lib/dhcp/dhcpd.leases"
DEFAULT_ISC_V6 = "/var/lib/dhcp/dhcpd6.leases"

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"

SERVER_LABELS = {"isc": "ISC", "kea": "Kea"}


def sniff_server(path):
    """Identify the DHCP server that wrote a lease file: 'kea', 'isc' or None.

    Kea's memfile is a CSV whose header names its columns; ISC's is a text
    file of ``lease``/``ia-na`` blocks.  Sniffing lets an explicitly supplied
    ``--v4-lease``/``--v6-lease`` path work without also naming ``--server``.
    """
    try:
        with open(path, "r", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return None

    for line in head.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("address,") or (
                line.startswith("address") and "," in line and "valid_lifetime" in line):
            return "kea"
        break

    if "binding state" in head or "ia-na " in head or head.lstrip().startswith("lease "):
        return "isc"
    return None


def kea_lease_path(family, explicit, config_dirs):
    """Resolve the Kea lease file for one family -> (path, note).

    An explicit ``--v4-lease``/``--v6-lease`` wins.  Otherwise the path is read
    from the Kea config, falling back to Kea's compiled-in default.

    ``path`` is ``None`` when Kea keeps its leases somewhere this tool cannot
    read -- a database backend, or a non-persistent memfile -- and ``note``
    then explains why, so the caller can say so rather than warning about a
    lease file that was never supposed to exist.
    """
    if explicit:
        return explicit, None
    source = discover_lease_source(family, config_dirs)
    if not source.readable:
        return None, source.note
    return source.path, source.note


def detect_servers(args, config_dirs):
    """Return the list of servers to report on, for ``--server auto``.

    Detection order: an explicitly named lease file is sniffed; otherwise a
    server counts as present when its config or any of its lease files (LFC
    generations included) exists.  Falling back to ISC when nothing at all is
    found preserves the historical behaviour of a bare invocation, warnings
    about the missing ISC lease file and all.
    """
    for explicit in (args.v4_lease, args.v6_lease):
        if explicit:
            sniffed = sniff_server(explicit)
            if sniffed:
                return [sniffed]

    found = []

    isc_present = any(os.path.exists(p) for p in (DEFAULT_ISC_V4, DEFAULT_ISC_V6))
    if isc_present:
        found.append("isc")

    kea_present = any(find_config(f, config_dirs) for f in ("4", "6"))
    if not kea_present:
        for family in ("4", "6"):
            source = discover_lease_source(family, config_dirs)
            if source.path and kea_lease_files(source.path):
                kea_present = True
                break
    if kea_present:
        found.append("kea")

    return found or ["isc"]


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


def _report_family(server, family, explicit, args, config_dirs):
    """Print one address-family section for one server; return its leases.

    Nothing is parsed when the server has no readable lease file for this
    family: the note says where the leases actually are, and warning about a
    missing CSV on top of that would only mislead.
    """
    if server == "kea":
        path, note = kea_lease_path(family, explicit, config_dirs)
        parse = parse_kea_v4 if family == "4" else parse_kea_v6
    else:
        default = DEFAULT_ISC_V4 if family == "4" else DEFAULT_ISC_V6
        path, note = (explicit or default), None
        parse = parse_isc_v4 if family == "4" else parse_isc_v6

    if note:
        print(f"{YELLOW}[NOTE] {note}{RESET}")

    if path is None:
        print(f"{BOLD}{CYAN}[ DHCPv{family} Leases ]{RESET}  "
              f"{DIM}no lease file to read{RESET}")
        return []

    leases = parse(path)
    active = sum(1 for l in leases
                 if l.state == "active" and not is_expired(l.expires))
    print(f"{BOLD}{CYAN}[ DHCPv{family} Leases ]{RESET}  "
          f"{DIM}file: {path}  total: {len(leases)}  active: {active}{RESET}")
    print_leases(leases, show_expired=args.all, filter_state=args.state)
    return leases


def _report_server(server, args, config_dirs):
    """Print the lease sections for one server; return the parsed leases."""
    print(f"{BOLD}--- {SERVER_LABELS[server]} DHCP ---{RESET}")

    leases = []
    if not args.v6_only:
        leases.extend(_report_family(server, "4", args.v4_lease, args, config_dirs))
    if not args.v4_only:
        leases.extend(_report_family(server, "6", args.v6_lease, args, config_dirs))
    return leases


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dhcp-lease-list",
        description=f"Unified DHCP lease viewer for ISC and Kea DHCP  v{__version__}"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--server", choices=["auto", "isc", "kea", "both"], default="auto",
                        help="DHCP server type: auto (default; detect what is "
                             "installed), isc, kea, or both")
    parser.add_argument("--v4-lease", default=None,
                        help="Path to IPv4 lease file (auto-selected based on --server if omitted)")
    parser.add_argument("--v6-lease", default=None,
                        help="Path to IPv6 lease file (auto-selected based on --server if omitted)")
    parser.add_argument("--kea-config-dir", default=None,
                        help="Directory holding kea-dhcp4.conf / kea-dhcp6.conf "
                             "(default: %s)" % ", ".join(DEFAULT_CONFIG_DIRS))
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

    config_dirs = (args.kea_config_dir,) if args.kea_config_dir else DEFAULT_CONFIG_DIRS

    if args.server == "auto":
        servers = detect_servers(args, config_dirs)
    elif args.server == "both":
        servers = ["isc", "kea"]
    else:
        servers = [args.server]

    label = " + ".join(SERVER_LABELS[s] for s in servers)
    print(f"\n{BOLD}=== {label} DHCP Unified Lease List  v{__version__} ==={RESET}")
    print(f"{DIM}Active leases shown. Use --all to include expired/free.{RESET}\n")

    all_leases = []
    for server in servers:
        all_leases.extend(_report_server(server, args, config_dirs))

    if args.conflicts:
        conflicts = find_conflicts(all_leases)
        has_high = _print_conflicts(conflicts)
        if has_high:
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
