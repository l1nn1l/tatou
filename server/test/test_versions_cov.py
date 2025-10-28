"""
Positive coverage tests for version-related endpoints:
- /api/get-version/<link>  (serves a PDF for 'external' links)
- /api/list-versions       (returns JSON list for a given document)
- /api/list-all-versions   (returns JSON list for current user)
"""

import os
import pytest
from flask import g
from server import app

# Test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"


# ---- minimal SQLA-like helpers ----
class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Result:
    def __init__(self, rows=None):
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            rows = [rows]
        self._rows = rows

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return list(self._rows)

    def one(self):
        if len(self._rows) != 1:
            raise Exception("Expected exactly one row")
        return self._rows[0]

    def scalar(self):
        r = self.first()
        return None if r is None else getattr(r, "scalar", None)


@pytest.fixture
def client(monkeypatch, tmp_path):
    """
    Flask test client with:
      - g.user injection on specific endpoints via app.view_functions wrapping
      - STORAGE_DIR pointed to tmp_path
      - get_engine patched to a fake engine returning deterministic rows
    """
    # Point storage at temp and create a real PDF to serve
    app.config["STORAGE_DIR"] = tmp_path
    pdf_dir = tmp_path / "files"
    pdf_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = pdf_dir / "served.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%happy\n")

    LINK = "validlink"
    DOC_ID = 123
    USER_LOGIN = "tester"

    # --- Wrap endpoints to inject g.user before handler runs ---
    def _wrap_with_user(fn):
        def _wrapped(*a, **kw):
            g.user = {"id": 1, "login": USER_LOGIN, "email": "tester@example.com"}
            return fn(*a, **kw)
        return _wrapped

    for endpoint in ("list_versions", "list_all_versions"):
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = _wrap_with_user(app.view_functions[endpoint])

    # --- Fake DB engine ---
    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): pass

        def execute(self, sql, params=None):
            s = str(sql)
            p = params or {}

            # get_version early path:
            # SELECT path, intended_for FROM Versions WHERE link = :link LIMIT 1
            if "FROM Versions" in s and "WHERE link = :link" in s and "SELECT path, intended_for" in s:
                if (p.get("link") or "") == LINK:
                    # Must be tuple-like so row[0], row[1] works
                    return _Result([(str(pdf_path), "external")])
                return _Result([])

            # list_versions join
            if (
                "FROM Users u" in s and "JOIN Documents d" in s and "JOIN Versions v" in s
                and "WHERE u.login = :glogin" in s and "d.id = :did" in s
            ):
                if p.get("glogin") == USER_LOGIN and int(p.get("did")) == DOC_ID:
                    rows = [
                        _Row(id=1, documentid=DOC_ID, link=LINK, intended_for="external", secret="s", method="m"),
                        _Row(id=2, documentid=DOC_ID, link="other", intended_for="team",     secret="x", method="n"),
                    ]
                    return _Result(rows)
                return _Result([])

            # list_all_versions join
            if (
                "FROM Users u" in s and "JOIN Documents d" in s and "JOIN Versions v" in s
                and "WHERE u.login = :glogin" in s and "d.id = v.documentid" in s
            ):
                if p.get("glogin") == USER_LOGIN:
                    rows = [
                        _Row(id=3, documentid=DOC_ID, link="abc", intended_for="team",     method="m"),
                        _Row(id=4, documentid=DOC_ID, link="def", intended_for="external", method="n"),
                    ]
                    return _Result(rows)
                return _Result([])

            # default
            return _Result([])

    class _Engine:
        def connect(self): return _Conn()
        def begin(self):   return _Conn()

    monkeypatch.setattr("server.get_engine", lambda _app: _Engine())

    # If the route falls back to the token path, make it succeed
    monkeypatch.setattr("server.verify_token", lambda token: (True, LINK), raising=False)

    # Build client and stash identifiers for tests
    test_client = app.test_client()
    test_client._test_link = LINK
    test_client._test_doc_id = DOC_ID
    return test_client


def test_get_version_endpoint_happy_external(client):
    """Serve a real PDF via the 'external' link path."""
    link = client._test_link
    resp = client.get(f"/api/get-version/{link}")
    assert resp.status_code == 200, resp.data
    assert resp.mimetype == "application/pdf"
    assert b"%PDF" in resp.data


def test_list_versions_happy(client):
    """Both path param and query param variants return JSON list."""
    did = client._test_doc_id

    resp = client.get(f"/api/list-versions/{did}")
    assert resp.status_code == 200, resp.data
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "versions" in data and isinstance(data["versions"], list)

    resp2 = client.get(f"/api/list-versions?id={did}")
    assert resp2.status_code == 200, resp2.data
    data2 = resp2.get_json()
    assert isinstance(data2, dict)
    assert "versions" in data2 and isinstance(data2["versions"], list)


def test_list_all_versions_happy(client):
    """Current user's versions list returns 200 + versions array."""
    resp = client.get("/api/list-all-versions")
    assert resp.status_code == 200, resp.data
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "versions" in data and isinstance(data["versions"], list)
