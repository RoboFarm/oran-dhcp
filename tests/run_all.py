#!/usr/bin/env python3
"""
Stdlib test runner for dhcp-oru-toolkit (no pytest required).

Discovers every tests/test_*.py module, imports it, calls each top-level
callable named test_*, and prints PASS/FAIL per test.  Exits 1 if any test
fails (or errors), 0 otherwise.

Usage:
    python tests/run_all.py
    PYTHONPATH=src python tests/run_all.py
    python -m tests.run_all

The runner is self-sufficient: it puts the repo `src/` on sys.path and the
test modules themselves ensure fixtures exist (via tools/make_fixtures).
"""

import os
import sys
import glob
import types
import inspect
import traceback
import importlib.util

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(THIS_DIR)
SRC_DIR = os.path.join(REPO_ROOT, "src")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

# Defensive path setup so the runner works from any cwd / without PYTHONPATH.
for p in (SRC_DIR, TOOLS_DIR, THIS_DIR, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)


# ANSI helpers (auto-disabled when not a TTY or NO_COLOR is set).
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code, s):
    if not _USE_COLOR:
        return s
    return "\033[%sm%s\033[0m" % (code, s)


def _green(s):
    return _c("32", s)


def _red(s):
    return _c("31", s)


def _dim(s):
    return _c("2", s)


def _load_module(path):
    """Import a test module from its file path under a unique module name."""
    name = "test_mod_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _callable_takes_no_required_args(fn):
    """True if fn can be called with zero positional arguments."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return True
    for param in sig.parameters.values():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if param.default is inspect.Parameter.empty and param.kind in (
            param.POSITIONAL_ONLY,
            param.POSITIONAL_OR_KEYWORD,
            param.KEYWORD_ONLY,
        ):
            return False
    return True


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pattern = os.path.join(THIS_DIR, "test_*.py")
    files = sorted(glob.glob(pattern))

    # Optional filter: substrings to match against "module::test" identifiers.
    filters = [a for a in argv if not a.startswith("-")]

    total = 0
    passed = 0
    failures = []  # (id, exc_text)

    for path in files:
        modname = os.path.basename(path)
        try:
            module = _load_module(path)
        except Exception:
            tb = traceback.format_exc()
            ident = "%s::<import>" % modname
            print("%s %s" % (_red("FAIL"), ident))
            print(_dim(tb))
            failures.append((ident, tb))
            total += 1
            continue

        tests = []
        for name, obj in vars(module).items():
            if name.startswith("test_") and isinstance(
                obj, (types.FunctionType, types.BuiltinFunctionType)
            ):
                tests.append((name, obj))
        tests.sort(key=lambda kv: kv[0])

        for name, fn in tests:
            ident = "%s::%s" % (modname, name)
            if filters and not any(f in ident for f in filters):
                continue
            total += 1
            try:
                if _callable_takes_no_required_args(fn):
                    fn()
                else:
                    # Tests should not require args; skip-call gracefully.
                    fn()
                print("%s %s" % (_green("PASS"), ident))
                passed += 1
            except Exception:
                tb = traceback.format_exc()
                print("%s %s" % (_red("FAIL"), ident))
                print(_dim(tb))
                failures.append((ident, tb))

    print()
    print(
        "%d passed, %d failed, %d total"
        % (passed, total - passed, total)
    )
    if failures:
        print(_red("FAILURES:"))
        for ident, _tb in failures:
            print("  - %s" % ident)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
