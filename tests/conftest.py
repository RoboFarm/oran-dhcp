"""
pytest bootstrap: ensure the repo `src/` (and `tools/`) dirs are importable
before any test module is collected, regardless of how pytest is invoked.

This mirrors the defensive sys.path setup in tests/_helpers.py and
tests/run_all.py so the suite runs identically under pytest and under the
stdlib runner.
"""

import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)

for _p in (
    os.path.join(_REPO_ROOT, "src"),
    os.path.join(_REPO_ROOT, "tools"),
    _THIS_DIR,
):
    if _p not in sys.path:
        sys.path.insert(0, _p)
