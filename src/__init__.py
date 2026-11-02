"""Autonomous AI SecOps Log Analyzer."""

import sys
from pathlib import Path

_vendor_path = str(Path(__file__).resolve().parent / "vendor")
if _vendor_path not in sys.path:
    sys.path.insert(0, _vendor_path)
