from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "server" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
