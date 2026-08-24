"""DHCP lease-file parsers (ISC + Kea, DHCPv4 + DHCPv6).

Ported from ``dhcp_lease_list_v1.3.0.py``; every parser returns ``list[Lease]``.

All bugfix logic noted in the original changelog (1.0 -> 1.3) is preserved:

* DUID MAC extraction for DUID-LLT (type 1), DUID-LL (type 3) and DUID-EN
  (type 2 ASCII scan), including the 4-byte IAID prefix on the ``ia-na`` key
  (changelog 1.1.0 / 1.1.1 / 1.2.0 / 1.2.1).
* ISC journal-aware dedup: keep the most recent *active* lease per IP
  (active always beats non-active; for equal states the later expiry wins).

The Kea parsers follow Kea's own memfile semantics instead (see
:func:`parse_kea_v4`): the lease file is a journal that is replayed in order,
the last row for an address wins, and a row with ``valid_lifetime = 0`` deletes
the address.  They also read the lease files left behind by Lease File Cleanup
(LFC) so leases are still listed while a cleanup is in flight.

Pure stdlib only.
"""

import os
import re
import csv
import json
from datetime import datetime, timezone
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

    return mac_from_duid_bytes(raw[IAID_LEN:])


def mac_from_duid_bytes(duid):
    """Extract a MAC from raw DUID bytes (no IAID prefix) -> 'xx:..' or '-'.

    This is the byte-level core shared by the ISC parser (which must first
    un-escape the lease-file text and strip ISC's 4-byte IAID prefix) and the
    Kea parsers (whose CSV stores the bare DUID as colon-separated hex).

    Handles DUID-LLT (type 1), DUID-EN (type 2, O-RAN units write the MAC as
    ASCII inside the enterprise identifier) and DUID-LL (type 3).
    """
    if not duid or len(duid) < 2:
        return "-"

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

# Kea escapes characters that would break its CSV (notably the comma inside a
# user-context JSON blob) as an XML-style hex entity.
_HEX_ESC_RE = re.compile(r'&#x([0-9a-fA-F]{2});')

# user-context keys that may carry a vendor class, checked at any nesting depth.
_VENDOR_CLASS_KEYS = ("vendor-class", "vendor_class",
                      "vendor-class-identifier", "vendor_class_identifier")


def kea_unescape(value):
    """Decode Kea's ``&#xNN;`` CSV escapes back to plain text."""
    if not value or "&#x" not in value:
        return value
    return _HEX_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), value)


def hex_to_bytes(text):
    """Parse Kea's colon-separated hex (``34:fe:9e:..``) into ``bytes``.

    Accepts ``-`` separators and unseparated hex too.  Returns ``b''`` for
    anything that is not clean hex, so callers never have to guard.
    """
    if not text:
        return b""
    cleaned = text.strip().replace(":", "").replace("-", "").replace(" ", "")
    if not cleaned or len(cleaned) % 2:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def mac_from_kea_duid(duid_text):
    """Extract a MAC from a Kea CSV ``duid`` column value -> 'xx:..' or '-'.

    Kea stores the bare DUID as colon-separated hex, with no ISC-style IAID
    prefix (the IAID is a column of its own), so the bytes go straight to
    :func:`mac_from_duid_bytes`.
    """
    return mac_from_duid_bytes(hex_to_bytes(duid_text))


def mac_from_kea_client_id(client_id_text):
    """Extract a MAC from a Kea CSV ``client_id`` column value (DHCPv4 opt 61).

    Two encodings appear in the field:

    * RFC 2132 -- htype ``0x01`` followed by the 6-byte MAC.
    * RFC 4361 -- type ``0xff`` followed by a 4-byte IAID and a DUID.

    A bare 6-byte value is accepted as a MAC as well.  Returns ``'-'`` when the
    option carries no link-layer address (an opaque string client-id, say).
    """
    raw = hex_to_bytes(client_id_text)
    if not raw:
        return "-"
    if len(raw) == 7 and raw[0] == 0x01:
        return ":".join(f"{b:02x}" for b in raw[1:7])
    if raw[0] == 0xFF and len(raw) > 5:
        return mac_from_duid_bytes(raw[5:])
    if len(raw) == 6:
        return ":".join(f"{b:02x}" for b in raw)
    return "-"


def epoch_to_datetime(epoch_str):
    """Convert a Unix epoch string to ``'YYYY/MM/DD HH:MM:SS'`` UTC (or '-').

    Kea records lease expiry as a Unix timestamp while ISC writes UTC wall
    clock into its lease files.  Rendering the Kea value in UTC too keeps the
    single "Expires (UTC)" column honest for both servers, and keeps
    :func:`~dhcp_toolkit.leases.display.is_expired` comparing like with like.
    """
    try:
        ts = int(epoch_str)
    except (TypeError, ValueError):
        return "-"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "-"


def path_present(path):
    """True if ``path`` exists, *including* when it exists but is unreadable.

    ``Path.exists()`` cannot be used for this.  When a parent directory is not
    searchable it raises ``PermissionError`` on Python 3.12 and older, and
    quietly returns False on 3.13 and newer (pathlib changed to swallow every
    OSError).  Either way a lease file that is present but unreadable came out
    as "not found", which points the operator at the wrong problem: the stock
    Ubuntu Kea package ships /var/lib/kea and its lease files owned by _kea and
    unreadable by anyone else, so every unprivileged run looked like an empty
    server instead of a missing sudo.

    Only a genuine ENOENT counts as absent here.  A permission error means the
    file *is* there, so it stays in the candidate list and the read that
    follows reports the real reason.
    """
    try:
        os.stat(path)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def kea_lease_files(path):
    """Return every existing lease file for a Kea memfile path, oldest first.

    Kea's Lease File Cleanup (LFC) does not rewrite the lease file in place.
    It moves the current file aside, starts a fresh one, and consolidates the
    old generations through a set of suffixed files:

    ``<name>.1``          previous file, moved aside when LFC started
    ``<name>.2``          the input LFC is consolidating
    ``<name>.completed``  a finished consolidation not yet folded back in

    While a cleanup is in flight -- or for good, if LFC was interrupted by a
    crash or a power cut -- most of the leases live in those files and
    ``<name>`` holds only what has been written since.  Reading ``<name>``
    alone is why a perfectly healthy Kea server could show few or no leases
    here.  Kea itself reloads all of them on start-up; this mirrors that order
    so the newest generation is replayed last and wins.
    """
    files = []
    completed = path + ".completed"
    if path_present(completed):
        files.append(completed)
    else:
        for suffix in (".2", ".1"):
            candidate = path + suffix
            if path_present(candidate):
                files.append(candidate)
    if path_present(path):
        files.append(path)
    return files


def _vendor_class_from_user_context(raw):
    """Pull a vendor class out of a Kea ``user_context`` JSON blob, or '-'.

    Kea does not record the client's vendor class in the lease file by
    default, but deployments that stash it in user context (directly or under
    a nested key) get it displayed in the same column as the ISC leases.
    """
    text = kea_unescape((raw or "").strip())
    if not text:
        return "-"
    try:
        obj = json.loads(text)
    except ValueError:
        return "-"

    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() in _VENDOR_CLASS_KEYS and isinstance(value, str) and value:
                    return value
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(n for n in node if isinstance(n, (dict, list)))
    return "-"


def _read_kea_rows(path, family):
    """Yield CSV rows from a Kea memfile lease file and its LFC generations.

    Emits nothing (after a single warning) when no generation exists.
    """
    files = kea_lease_files(path)
    if not files:
        print(f"{YELLOW}[WARN] Kea DHCPv{family} lease file not found: {path}{RESET}")
        return

    denied_reported = False
    for filename in files:
        try:
            text = Path(filename).read_text(errors="replace")
        except FileNotFoundError:
            # Raced with LFC between the existence check and the read.
            continue
        except PermissionError:
            # Reported once per parse, naming the directory rather than each
            # candidate: when the directory itself is unsearchable we cannot
            # tell which of the LFC generations are really there, so listing
            # them individually would invent files that may not exist.
            if not denied_reported:
                directory = os.path.dirname(filename) or "."
                print(f"{RED}[ERROR] Permission denied reading the Kea DHCPv{family} "
                      f"lease files in {directory} -- re-run with sudo{RESET}")
                denied_reported = True
            continue

        if filename != path:
            print(f"{YELLOW}[NOTE] also reading Kea LFC generation {filename} "
                  f"(lease file cleanup in progress or interrupted){RESET}")

        for row in csv.DictReader(text.splitlines()):
            yield row


def _apply_kea_row(leases, ip, valid_lft, lease):
    """Apply one journal row to the accumulated lease map, Kea-style.

    Kea's memfile is a journal replayed in order: the last row for an address
    is the truth, and a row whose ``valid_lifetime`` is ``0`` is Kea's marker
    for a *deleted* lease and removes the address entirely.  (The previous
    implementation kept whichever row was ``active``, which left released and
    reclaimed addresses on display as though they were still held.)
    """
    try:
        if int(valid_lft) == 0:
            leases.pop(ip, None)
            return
    except (TypeError, ValueError):
        pass
    leases[ip] = lease


def parse_kea_v4(path):
    """Parse a Kea DHCPv4 CSV lease file (``kea-leases4.csv``) -> list[Lease].

    Columns: address, hwaddr, client_id, valid_lifetime, expire, subnet_id,
    fqdn_fwd, fqdn_rev, hostname, state, user_context, pool_id.  Unknown extra
    columns from newer Kea releases are ignored, and missing ones tolerated.

    State: 0=active, 1=declined, 2=expired-reclaimed, 3=released.

    The lease file plus any LFC generations (see :func:`kea_lease_files`) are
    replayed in order; the last row per address wins and ``valid_lifetime = 0``
    deletes it.  When Kea did not record a ``hwaddr`` the MAC is recovered from
    the option 61 ``client_id``.
    """
    leases = {}
    for row in _read_kea_rows(path, "4"):
        try:
            ip = (row.get("address") or "").strip()
            if not ip:
                continue

            state_code = (row.get("state") or "0").strip()
            state = KEA_STATES.get(state_code, f"state-{state_code}")

            mac = (row.get("hwaddr") or "").strip()
            if not mac:
                mac = mac_from_kea_client_id(row.get("client_id"))

            hostname = kea_unescape((row.get("hostname") or "").strip()) or "-"
            valid_lft = (row.get("valid_lifetime") or "").strip()
            expire = epoch_to_datetime((row.get("expire") or "").strip())

            lease = Lease(
                ip=ip, version="4", server="kea", state=state,
                mac=mac or "-", hostname=hostname, expires=expire,
                starts=_kea_starts(row.get("expire"), valid_lft),
                vendor_class=_vendor_class_from_user_context(row.get("user_context")),
                valid_lft=valid_lft or "-",
            )
            _apply_kea_row(leases, ip, valid_lft, lease)
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

    Journal replay is as described for :func:`parse_kea_v4`.  Kea only fills
    the ``hwaddr`` column when it could derive a link-layer address from the
    exchange (see its ``mac-sources`` setting), and leaves it empty otherwise
    -- for a relayed exchange, for instance.  Where it is empty the MAC is
    recovered from the DUID, exactly as the ISC DHCPv6 parser does, so O-RUs
    are identifiable by MAC on either server.
    """
    leases = {}
    for row in _read_kea_rows(path, "6"):
        try:
            ip = (row.get("address") or "").strip()
            if not ip:
                continue

            # Skip prefix delegation entries (lease_type=2); show addresses only.
            if (row.get("lease_type") or "0").strip() == "2":
                continue

            state_code = (row.get("state") or "0").strip()
            state = KEA_STATES.get(state_code, f"state-{state_code}")

            duid = (row.get("duid") or "").strip()
            mac = (row.get("hwaddr") or "").strip()
            if not mac:
                mac = mac_from_kea_duid(duid)

            hostname = kea_unescape((row.get("hostname") or "").strip()) or "-"
            valid_lft = (row.get("valid_lifetime") or "").strip()
            expire = epoch_to_datetime((row.get("expire") or "").strip())

            lease = Lease(
                ip=ip, version="6", server="kea", state=state,
                mac=mac or "-", hostname=hostname, expires=expire,
                starts=_kea_starts(row.get("expire"), valid_lft),
                vendor_class=_vendor_class_from_user_context(row.get("user_context")),
                duid=duid or "-", valid_lft=valid_lft or "-",
            )
            _apply_kea_row(leases, ip, valid_lft, lease)
        except Exception:
            continue

    return list(leases.values())


def _kea_starts(expire_raw, valid_lft):
    """Derive the lease start time from Kea's expiry and lifetime columns.

    Kea stores no start time, but ``expire - valid_lifetime`` is exactly the
    client-last-transaction time, which is what the ISC parsers put in this
    column.
    """
    try:
        expire = int((expire_raw or "").strip())
        lifetime = int(valid_lft)
    except (TypeError, ValueError):
        return "-"
    if lifetime <= 0:
        return "-"
    return epoch_to_datetime(expire - lifetime)
