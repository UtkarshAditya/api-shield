"""Root pytest config: lets a plain `pytest` from the repo root collect every package's tests.

The learning package (M3) imports itself as top-level `apishield_learning`, so `learning/` must
be on sys.path (the same as running with PYTHONPATH=learning). Nothing inside learning/ changes.
"""
import sys
from pathlib import Path

_LEARNING = str(Path(__file__).resolve().parent / "learning")
if _LEARNING not in sys.path:
    sys.path.insert(0, _LEARNING)
