# tatou/server/test/conftest.py
import sys
from pathlib import Path

# Add the "src" folder (where server.py lives) to sys.path
SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
