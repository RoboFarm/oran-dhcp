"""Lease table rendering and state helpers.

Ported from ``dhcp_lease_list_v1.3.0.py``.  Operates on ``Lease`` dataclasses.
``print_leases(..., use_color=False)`` strips all ANSI styling so output is
clean for pipes, files and tests.

Pure stdlib only.
"""

from datetime import datetime, timezone

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"


def is_expired(expires_str):
    """Return True if a ``'YYYY/MM/DD HH:MM:SS'`` timestamp is in the past.

    Lease timestamps are UTC on both servers -- ISC writes UTC wall clock into
    its lease files, and the Kea parser renders its epoch column as UTC -- so
    the comparison is against UTC now, not local now.  Comparing a UTC lease
    against a local clock silently hid still-valid leases on any server east
    of Greenwich (and kept expired ones on display west of it).
    """
    try:
        exp = datetime.strptime(expires_str, "%Y/%m/%d %H:%M:%S")
        return exp < datetime.now(timezone.utc).replace(tzinfo=None)
    except Exception:
        return False


def state_color(state, expires):
    """Return a coloured state string (ANSI)."""
    if state == "active" and not is_expired(expires):
        return f"{GREEN}{state}{RESET}"
    elif state in ("free", "released"):
        return f"{DIM}{state}{RESET}"
    else:
        return f"{YELLOW}{state}{RESET}"


def print_leases(leases, show_expired=False, filter_state=None, use_color=True):
    """Pretty-print a lease table.

    ``leases`` is a list of ``Lease`` dataclasses.  Active leases whose expiry
    is in the past are hidden unless ``show_expired`` is True.  ``filter_state``
    restricts to a single binding state.  When ``use_color`` is False all ANSI
    escapes are suppressed.
    """
    if not leases:
        return

    # Color shims: when color is disabled, every token becomes the empty string.
    c_reset = RESET if use_color else ""
    c_bold = BOLD if use_color else ""
    c_cyan = CYAN if use_color else ""
    c_dim = DIM if use_color else ""

    if not show_expired:
        leases = [l for l in leases
                  if not (l.state == "active" and is_expired(l.expires))]
    if filter_state:
        leases = [l for l in leases if l.state == filter_state]

    if not leases:
        print(f"  {c_dim}No leases to display.{c_reset}\n")
        return

    w_ip = max(len(l.ip) for l in leases) + 2
    w_mac = max(len(l.mac or "-") for l in leases) + 2
    w_host = max(len(l.hostname or "-") for l in leases) + 2
    w_exp = 22
    w_vc = max(len(l.vendor_class or "-") for l in leases) + 2

    header = (f"{'IP Address':<{w_ip}} {'MAC / DUID':<{w_mac}} "
              f"{'Hostname':<{w_host}} {'State':<12} "
              f"{'Expires (UTC)':<{w_exp}} {'Vendor Class':<{w_vc}}")
    sep = "-" * len(header)

    print(f"{c_bold}{header}{c_reset}")
    print(sep)

    for l in sorted(leases, key=lambda x: x.ip):
        ip = l.ip
        mac = l.mac or "-"
        hostname = l.hostname or "-"
        state = l.state or "-"
        expires = l.expires or "-"
        vc = l.vendor_class or "-"

        if use_color:
            colored_state = state_color(state, expires)
            # Pad to a visual width of 12 accounting for the invisible ANSI codes.
            state_w = 12 + len(colored_state) - len(state)
            print(f"{c_cyan}{ip:<{w_ip}}{c_reset} {mac:<{w_mac}} "
                  f"{hostname:<{w_host}} {colored_state:<{state_w}} "
                  f"{expires:<{w_exp}} {c_dim}{vc}{c_reset}")
        else:
            print(f"{ip:<{w_ip}} {mac:<{w_mac}} "
                  f"{hostname:<{w_host}} {state:<12} "
                  f"{expires:<{w_exp}} {vc}")
    print()
