# tatou/server/test/conftest.py
import sys
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
