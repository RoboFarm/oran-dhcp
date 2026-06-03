"""
Shared test helpers (pure stdlib).

This is intentionally NOT named test_*.py so the stdlib runner / pytest do not
treat it as a test module.

Responsibilities:
  * Defensively put the repo `src/` dir on sys.path so tests run with or without
    PYTHONPATH set, under pytest AND under tests/run_all.py.
  * Locate the repo root, tools/, and tests/fixtures/ regardless of cwd.
  * Build the fixtures by importing and running tools/make_fixtures (so the test
    suite is self-sufficient and does not require a separate build step).
  * Provide tolerant fixture-path lookup helpers.
"""

import os
import sys
import importlib

# --------------------------------------------------------------------------
# Path discovery
# --------------------------------------------------------------------------

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(THIS_DIR)
SRC_DIR = os.path.join(REPO_ROOT, "src")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
FIXTURES_DIR = os.path.join(THIS_DIR, "fixtures")
SAMPLES_DIR = os.path.join(REPO_ROOT, "samples")

# Defensively make src/ importable no matter how the tests are launched.
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
# tools/ is a flat module dir (make_fixtures.py), make it importable too.
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)


# --------------------------------------------------------------------------
# Fixture generation
# --------------------------------------------------------------------------

_FIXTURES_BUILT = False


def ensure_fixtures():
    """
    Ensure the test fixtures exist by importing and running tools/make_fixtures.

    The fixtures agent owns tools/make_fixtures.py.  It must expose either a
    `main()` or a `build(out_dir=...)`/`make_fixtures(out_dir=...)` callable, or
    simply create the fixtures as a side-effect of import.  We try the common
    shapes and then verify that at least the core fixtures landed on disk.

    Idempotent: safe to call from every test module.
    """
    global _FIXTURES_BUILT
    if _FIXTURES_BUILT:
        return
    os.makedirs(FIXTURES_DIR, exist_ok=True)

    mod = None
    try:
        mod = importlib.import_module("make_fixtures")
    except Exception:
        # Fall back to a package-qualified import if tools is a package.
        try:
            mod = importlib.import_module("tools.make_fixtures")
        except Exception:
            mod = None

    if mod is not None:
        ran = False
        # Try the most specific callable shapes first, passing the output dir
        # where our tests look for fixtures.
        for name in ("build", "make_fixtures", "build_fixtures", "generate", "write_all"):
            fn = getattr(mod, name, None)
            if callable(fn):
                for kwargs in ({"out_dir": FIXTURES_DIR}, {"outdir": FIXTURES_DIR},
                               {"dest": FIXTURES_DIR}, {}):
                    try:
                        fn(**kwargs)
                        ran = True
                        break
                    except TypeError:
                        continue
                    except Exception:
                        # A build error here will surface as a missing-fixture
                        # assertion below, which is the clearer failure.
                        ran = True
                        break
                if ran:
                    break
        if not ran:
            main = getattr(mod, "main", None)
            if callable(main):
                try:
                    main()
                except SystemExit:
                    pass
                except Exception:
                    pass

    _FIXTURES_BUILT = True


# --------------------------------------------------------------------------
# Fixture lookup (tolerant to where the fixtures agent placed files)
# --------------------------------------------------------------------------

def fixture_path(*names, required=True):
    """
    Return the path to the first existing fixture matching one of *names*.

    Searches tests/fixtures/ (recursively), then samples/, then the repo root.
    Accepts multiple candidate base names so tests survive minor naming choices.
    """
    search_roots = [FIXTURES_DIR, SAMPLES_DIR, REPO_ROOT]
    # First: direct hits in the fixtures dir (fast path / preferred location).
    for name in names:
        cand = os.path.join(FIXTURES_DIR, name)
        if os.path.exists(cand):
            return cand
    # Then: recursive search under each root.
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in names:
                base = os.path.basename(name)
                if base in files:
                    return os.path.join(dirpath, base)
    if required:
        raise AssertionError(
            "fixture not found (looked for %r under %s); "
            "is tools/make_fixtures producing it?"
            % (list(names), search_roots)
        )
    return None


def real_pcap_path():
    """Path to the genuine O-RU fronthaul capture shipped in the repo."""
    return fixture_path("oru_real_capture.pcap")


# --------------------------------------------------------------------------
# Documented ground-truth from the bug report (used across tests)
# --------------------------------------------------------------------------

# Per-unit chaddr MACs (last-two-octet shorthand -> full MAC).
MAC_A1_ADA8 = "34:fe:9e:3d:ad:a8"   # serial A2256600363
MAC_A2_AF5C = "34:fe:9e:3d:af:5c"   # serial A1770000213
MAC_A3_ADC8 = "34:fe:9e:3d:ad:c8"   # serial A2256600222 -- the thief

# Shared (reused) transaction-ids from the two documented sequences.
XID_SEQ1 = 0x8fc37a94
XID_SEQ2 = 0xcb07f611

# Contested addresses on 192.168.36.0/24.
IP_171 = "192.168.36.171"
IP_172 = "192.168.36.172"

VENDOR_PREFIX = "o-ran-ru2/FJ"


def has_ansi(s):
    """True if string contains an ANSI escape (ESC, chr 27)."""
    return chr(27) in s
