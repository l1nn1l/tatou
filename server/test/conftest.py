# tatou/server/test/conftest.py
import os
os.environ["TESTING"] = "1"
print("[pytest setup] TESTING=1 environment enabled")


import sys
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
