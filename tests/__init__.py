"""Test package marker.

This file makes the tests directory importable so unittest discovery works
correctly from the repository root.
"""

from __future__ import annotations

import os
import sys

TESTS_DIR = os.path.dirname(__file__)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
