"""
Positive coverage tests for document-related APIs:
- /api/upload-document
- /api/list-documents
- /api/get-document/<id>
- /api/delete-document/<id>
"""

import io
import os
import datetime as dt
import pytest
from pathlib import Path

from flask import g
from server import app

# test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"


# --- Tiny SQLA-ish helpers ---
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
            raise RuntimeError("expected exactly one row")
        return self._rows[0]

    def scalar(self):
        r = self.first()
        return None if r is None else getattr(r, "scalar", None)


@pytest.fixture
def client(monkeypatch, tmp_path):
    """
    Flask test client with:
      - g.user injection by wrapping specific endpoints
      - STORAGE_DIR pointing at tmp_path/storage
      - in-memory fake engine that matches queries in server.py
    """
    # Storage dir so file.save() works
    storage = tmp_path / "storage"
    (storage / "files" / "testuser").mkdir(parents=True, exist_ok=True)
    app.config["STORAGE_DIR"] = storage

    # Wrap the view functions we need to inject g.user (no late before_request)
    def _with_user(fn):
        def _wrapped(*a, **kw):
            g.user = {"id": 1, "login": "testuser", "email": "test@example.com"}
            return fn(*a, **kw)
        return _wrapped

    for endpoint in ("upload_document", "list_documents", "get_document", "delete_document"):
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = _with_user(app.view_functions[endpoint])

    # In-memory "DB"
    store = {
        "docs": {},      # id -> dict
        "next_id": 1,
        "last_id": None,
    }

    # Fake engine/connection implementing the exact SQL patterns used
    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): pass

        def execute(self, sql, params=None):
            s = str(sql)
            p = params or {}

            # INSERT INTO Documents (...)
            if "INSERT INTO Documents" in s:
                did = store["next_id"]
                store["next_id"] += 1
                store["last_id"] = did
                # pull values from params
                name = p.get("name", "unnamed.pdf")
                path = str(p.get("path", ""))
                ownerid = int(p.get("ownerid", 1))
                size = int(p.get("size", 0))
                sha256hex = p.get("sha256hex", "00" * 32)
                store["docs"][did] = {
                    "id": did,
                    "name": name,
                    "path": path,
                    "ownerid": ownerid,
                    "size": size,
                    "sha256_hex": sha256hex.upper(),
                    "creation": dt.datetime.utcnow(),
                }
                return _Result([])

            # SELECT LAST_INSERT_ID()
            if "LAST_INSERT_ID" in s:
                return _Result(_Row(scalar=store["last_id"]))

            # --- SPECIFIC branch FIRST: get_document needs path ---
            # SELECT id, name, path, HEX(sha256) AS sha256_hex, size
            # FROM Documents WHERE id = :id AND ownerid = :uid LIMIT 1
            if (
                "FROM Documents" in s
                and "WHERE id = :id AND ownerid = :uid" in s
                and "HEX(sha256) AS sha256_hex" in s
            ):
                did = int(p.get("id"))
                uid = int(p.get("uid"))
                doc = store["docs"].get(did)
                if not doc or doc["ownerid"] != uid:
                    return _Result([])
                return _Result(_Row(
                    id=doc["id"],
                    name=doc["name"],
                    path=doc["path"],
                    sha256_hex=doc["sha256_hex"],
                    size=doc["size"],
                ))

            # --- GENERIC list-by-owner (no path) ---
            # SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
            # FROM Documents WHERE ownerid = :uid ORDER BY creation DESC
            if (
                "FROM Documents" in s
                and "WHERE ownerid = :uid" in s
                and "HEX(sha256) AS sha256_hex" in s
                and "ORDER BY creation DESC" in s
            ):
                uid = int(p.get("uid"))
                rows = []
                for doc in sorted(store["docs"].values(), key=lambda d: d["creation"], reverse=True):
                    if doc["ownerid"] == uid:
                        rows.append(_Row(
                            id=doc["id"],
                            name=doc["name"],
                            creation=doc["creation"],
                            sha256_hex=doc["sha256_hex"],
                            size=doc["size"],
                        ))
                return _Result(rows)

            # --- AFTER the specific branch: the post-insert lookup (no path) ---
            # SELECT id, name, creation, HEX(sha256) AS sha256_hex, size WHERE id=:id
            if (
                "FROM Documents" in s
                and "WHERE id = :id" in s
                and "HEX(sha256) AS sha256_hex" in s
                and "creation" in s
            ):
                did = int(p.get("id"))
                doc = store["docs"].get(did)
                if not doc:
                    return _Result([])
                return _Result(_Row(
                    id=doc["id"],
                    name=doc["name"],
                    creation=doc["creation"],
                    sha256_hex=doc["sha256_hex"],
                    size=doc["size"],
                ))

            # DELETE path — the route first does: SELECT * FROM Documents WHERE id = <id>
            if "SELECT * FROM Documents WHERE id =" in s:
                try:
                    did = int(s.split("SELECT * FROM Documents WHERE id =")[1].strip())
                except Exception:
                    return _Result([])
                doc = store["docs"].get(did)
                if not doc:
                    return _Result([])
                return _Result(_Row(**doc))

            # DELETE FROM Documents WHERE id = :id
            if "DELETE FROM Documents WHERE id = :id" in s:
                did = int(p.get("id"))
                store["docs"].pop(did, None)
                return _Result([])

            # default
            return _Result([])

    class _Engine:
        def connect(self): return _Conn()
        def begin(self):   return _Conn()

    monkeypatch.setattr("server.get_engine", lambda _app: _Engine())

    return app.test_client()


def test_happy_path_upload_list_get_delete(client):
    # ---- Upload ----
    payload = io.BytesIO(b"%PDF-1.4 test-pdf")
    resp = client.post(
        "/api/upload-document",
        data={"file": (payload, "happy.pdf"), "name": "happy.pdf"},
        content_type="multipart/form-data",
    )
    assert resp.status_code in (200, 201), resp.data
    up = resp.get_json()
    assert isinstance(up, dict)
    doc_id = int(up["id"])

    # ---- List ----
    resp2 = client.get("/api/list-documents")
    assert resp2.status_code == 200, resp2.data
    data2 = resp2.get_json()
    assert isinstance(data2, dict)
    assert "documents" in data2
    assert any(d.get("id") == doc_id for d in data2["documents"])

    # ---- Get (should serve a file or 200/304) ----
    resp3 = client.get(f"/api/get-document/{doc_id}")
    assert resp3.status_code in (200, 304), resp3.data
    # If it's a file, mimetype will be application/pdf
    # We avoid asserting content to keep it lightweight.

    # ---- Delete ----
    resp4 = client.delete(f"/api/delete-document/{doc_id}")
    assert resp4.status_code == 200, resp4.data
    info = resp4.get_json()
    assert info.get("deleted") is True

    # ---- List again: should not contain the deleted doc ----
    resp5 = client.get("/api/list-documents")
    assert resp5.status_code == 200, resp5.data
    data5 = resp5.get_json()
    ids = [d.get("id") for d in data5.get("documents", [])]
    assert doc_id not in ids
