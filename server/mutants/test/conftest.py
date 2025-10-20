# tatou/server/test/conftest.py
import os
import sys
from pathlib import Path
import pytest

# --- Environment setup ---
os.environ["TESTING"] = "1"
print("[pytest setup] TESTING=1 environment enabled")

# --- Path setup ---
# Detect project root dynamically (should be .../tatou or similar)
ROOT = Path(__file__).resolve().parents[2]
# Move up until we find project root (where sample.pdf or pyproject.toml likely exists)
for parent in ROOT.parents:
    if (parent / "server").exists():
        ROOT = parent
        break

SRC = ROOT / "server" / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# --- Fixtures ---
@pytest.fixture
def sample_pdf_path(tmp_path: Path) -> Path:
    """
    Use a valid sample.pdf in the project root and copy it to a temp file
    so tests never modify the original.
    """
    src = ROOT / "sample.pdf"
    assert src.exists(), f"Missing test PDF at {src}"

    dst = tmp_path / "sample.pdf"
    dst.write_bytes(src.read_bytes())
    return dst
