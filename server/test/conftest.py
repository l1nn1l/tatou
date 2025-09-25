# tatou/server/test/conftest.py
import sys
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from server import app  
#allows all test files to reuse the same Flask test client
@pytest.fixture
def client():
    """Provide a test client for the Flask app."""
    return app.test_client()

# Base URL for the running Tatou server container
BASE_URL = "http://localhost:5000"

@pytest.fixture(scope="session")
def base_url():
    """Base URL for the running Tatou server container."""
    return BASE_URL