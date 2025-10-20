# server/test/conftest.py
import sys
from pathlib import Path
import pytest

# Repo-rot = .../tatou
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "server" / "src"

# Lägg server/src först i sys.path så att:
#  - "from server import app" hittar server/src/server.py
#  - "from plugins.xmp_perpage ..." hittar server/src/plugins/*
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

@pytest.fixture
def sample_pdf_path(tmp_path: Path) -> Path:
    """
    Använd en giltig sample.pdf i projektroten och kopiera till en temp-fil
    så att testerna aldrig rör originalet.
    """
    src = ROOT / "sample.pdf"
    assert src.exists(), f"Missing test PDF at {src}"

    dst = tmp_path / "sample.pdf"
    dst.write_bytes(src.read_bytes())
    return dst
