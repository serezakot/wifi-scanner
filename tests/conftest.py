"""
Pytest configuration shared by all tests.

The project currently mixes two import styles between modules:
  - control_api.py imports its siblings as "net_watch.bettercap" (package-style)
  - bettercap.py / arp_scan.py import their siblings flatly, e.g. "import traffic_colector"
    (expects the net_watch/ folder itself to be on sys.path)

Both styles need to resolve for the whole package to import cleanly, so we add
BOTH the project root (parent of net_watch/) and the net_watch/ folder itself
to sys.path. This is a workaround for tests, not a fix -- see the README note
about unifying the import style in the modules themselves.
"""
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
_PACKAGE_DIR = os.path.join(_PROJECT_ROOT, "net_watch")

for _path in (_PROJECT_ROOT, _PACKAGE_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)
