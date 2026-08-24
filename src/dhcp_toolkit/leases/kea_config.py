"""Kea DHCP configuration discovery.

``dhcp-lease-list`` used to assume Kea always keeps its leases in
``/var/lib/kea/kea-leases4.csv`` / ``kea-leases6.csv``.  That is only the
compiled-in default: the real location is whatever ``lease-database.name``
says in ``/etc/kea/kea-dhcp4.conf`` (respectively ``kea-dhcp6.conf``), and a
site may not use ``memfile`` at all -- Kea also supports MySQL and PostgreSQL
lease backends, where no CSV exists to read.

This module answers three questions without importing anything outside the
standard library:

1. Where is the Kea config for a given address family?
2. Which lease backend does it use?
3. If it is ``memfile``, what is the lease file path?

Kea's configuration is JSON *with extensions*: it accepts ``//``, ``#`` and
``/* ... */`` comments, and ``<?include "file"?>`` directives.  Neither is
valid JSON, so :func:`read_kea_config` strips comments and expands includes
before handing the text to :mod:`json`.

Every function here degrades gracefully: an unreadable, unparseable or absent
config yields a source that falls back to the documented default path rather
than raising.

Pure stdlib only.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Optional

# Compiled-in Kea defaults, used when no config can be read.
DEFAULT_KEA_V4 = "/var/lib/kea/kea-leases4.csv"
DEFAULT_KEA_V6 = "/var/lib/kea/kea-leases6.csv"

# Directories searched for kea-dhcp{4,6}.conf, in order.
DEFAULT_CONFIG_DIRS = ("/etc/kea", "/usr/local/etc/kea")

# Maximum <?include?> nesting depth, to stop an include cycle from hanging us.
_MAX_INCLUDE_DEPTH = 8

_INCLUDE_RE = re.compile(r'<\?include\s+"([^"]+)"\s*\?>')


@dataclass
class KeaLeaseSource:
    """Where (and whether) Kea leases can be read for one address family.

    ``path`` is set only for the ``memfile`` backend.  ``note`` carries a
    human-readable explanation whenever leases cannot be listed from a file,
    so the CLI can tell the operator *why* instead of printing an empty table.
    """
    family: str                      # '4' | '6'
    backend: str = "memfile"         # 'memfile' | 'mysql' | 'postgresql' | ...
    path: Optional[str] = None
    persist: bool = True
    config_path: Optional[str] = None
    note: Optional[str] = None

    @property
    def readable(self):
        """True when leases live in a CSV file this tool can parse."""
        return self.backend == "memfile" and self.persist and bool(self.path)


def strip_json_comments(text):
    """Remove ``//``, ``#`` and ``/* */`` comments from Kea-flavoured JSON.

    Comment markers inside string literals are left alone, and backslash
    escapes are honoured so that ``"a\\"# not a comment"`` survives intact.
    """
    out = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]

        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                # Copy the escaped character verbatim; it can never end the
                # string or start a comment.
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def expand_includes(text, base_dir, depth=0):
    """Inline Kea ``<?include "file"?>`` directives, relative to ``base_dir``.

    An include that cannot be read is replaced with nothing, which usually
    makes the surrounding JSON unparseable -- and an unparseable config is
    reported as "unknown" rather than silently mis-parsed.
    """
    if depth >= _MAX_INCLUDE_DEPTH:
        return text

    def _sub(match):
        target = match.group(1)
        if not os.path.isabs(target):
            target = os.path.join(base_dir, target)
        try:
            with open(target, "r") as fh:
                inner = fh.read()
        except OSError:
            return ""
        return expand_includes(inner, os.path.dirname(target), depth + 1)

    return _INCLUDE_RE.sub(_sub, text)


def read_kea_config(path):
    """Parse a Kea config file into a dict, or return ``None`` on any failure."""
    try:
        with open(path, "r") as fh:
            text = fh.read()
    except OSError:
        return None

    text = expand_includes(text, os.path.dirname(os.path.abspath(path)))
    text = strip_json_comments(text)
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def find_config(family, config_dirs=None):
    """Return the path to ``kea-dhcp<family>.conf``, or ``None`` if absent."""
    dirs = config_dirs if config_dirs is not None else DEFAULT_CONFIG_DIRS
    if isinstance(dirs, str):
        dirs = (dirs,)
    name = "kea-dhcp%s.conf" % family
    for d in dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand):
            return cand
    return None


def discover_lease_source(family, config_dirs=None):
    """Work out where Kea keeps its leases for address family ``family``.

    ``family`` is ``'4'`` or ``'6'``.  Always returns a :class:`KeaLeaseSource`;
    when no config is found or it cannot be parsed, the source falls back to
    the compiled-in default path so the tool still works on a stock install.
    """
    default_path = DEFAULT_KEA_V4 if str(family) == "4" else DEFAULT_KEA_V6
    family = str(family)

    config_path = find_config(family, config_dirs)
    if config_path is None:
        return KeaLeaseSource(family=family, path=default_path)

    cfg = read_kea_config(config_path)
    if cfg is None:
        return KeaLeaseSource(
            family=family, path=default_path, config_path=config_path,
            note="could not parse %s; falling back to the default lease file"
                 % config_path,
        )

    root = cfg.get("Dhcp%s" % family)
    if not isinstance(root, dict):
        return KeaLeaseSource(
            family=family, path=default_path, config_path=config_path,
            note="no Dhcp%s section in %s; falling back to the default lease file"
                 % (family, config_path),
        )

    db = root.get("lease-database")
    if not isinstance(db, dict):
        # A Dhcp4/Dhcp6 section without lease-database means Kea's own
        # memfile default is in force.
        return KeaLeaseSource(family=family, path=default_path,
                              config_path=config_path)

    backend = str(db.get("type", "memfile")).lower()
    if backend != "memfile":
        return KeaLeaseSource(
            family=family, backend=backend, path=None, config_path=config_path,
            note="Kea DHCPv%s uses the '%s' lease backend, not memfile; "
                 "there is no CSV lease file to read (query the database, or "
                 "use kea-shell with the lease%s-get-all command)"
                 % (family, backend, family),
        )

    persist = db.get("persist", True)
    if persist is False:
        return KeaLeaseSource(
            family=family, backend="memfile", path=None, persist=False,
            config_path=config_path,
            note="Kea DHCPv%s memfile has \"persist\": false; leases are held "
                 "in memory only and never written to disk" % family,
        )

    return KeaLeaseSource(
        family=family, backend="memfile",
        path=db.get("name") or default_path,
        config_path=config_path,
    )
