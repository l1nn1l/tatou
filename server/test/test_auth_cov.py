"""
Positive-path tests for /api/create-user and /api/login.
A minimal fake DB engine is used so routes execute their normal success logic.
"""

import os
import time
import datetime as dt
import pytest
from server import app

# Ensure test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"


# ---------- Minimal SQLA-like fakes tailored to server.py ----------
class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)

class _Result:
    def __init__(self, rows=None, *, lastrowid=None, rowcount=0):
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            rows = [rows]
        self._rows = rows
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def one(self):
        if len(self._rows) != 1:
            raise Exception("Expected exactly one row")
        return self._rows[0]

    def scalar(self):
        r = self.first()
        return None if r is None else getattr(r, "scalar", None)


class _Conn:
    def __init__(self, store):
        # store = {"users": {id: _Row(...)}, "next_user_id": int}
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def execute(self, sql, params=None):
        s = str(sql)
        p = params or {}

        # --- Users table emulation matching server.py exactly ---

        # INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)
        if "INSERT INTO Users" in s and "VALUES" in s:
            uid = self.store["next_user_id"]
            self.store["next_user_id"] += 1

            # server.py uses keys: email, hpw, login
            email = (p.get("email") or "").strip().lower()
            login = (p.get("login") or "")
            hpw = p.get("hpw") or ""  # hashed password value

            self.store["users"][uid] = _Row(
                id=uid,
                email=email,
                login=login,
                hpassword=hpw,               # server.login expects attribute named "hpassword"
                created_at=dt.datetime.utcnow(),
            )
            return _Result([], lastrowid=uid, rowcount=1)

        # SELECT id, email, login FROM Users WHERE id = :id
        if "FROM Users" in s and "WHERE id = :id" in s:
            uid = int(p.get("id"))
            u = self.store["users"].get(uid)
            if u:
                # ensure we return exactly the columns the route reads
                return _Result(_Row(id=u.id, email=u.email, login=u.login), rowcount=1)
            return _Result(None, rowcount=0)

        # SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1
        if "FROM Users" in s and "WHERE email = :email" in s:
            target_email = (p.get("email") or "").strip().lower()
            for u in self.store["users"].values():
                if (u.email or "").lower() == target_email:
                    return _Result(
                        _Row(id=u.id, email=u.email, login=u.login, hpassword=u.hpassword),
                        rowcount=1,
                    )
            return _Result(None, rowcount=0)

        # SELECT LAST_INSERT_ID() — not used in auth, but harmless to support
        if "LAST_INSERT_ID" in s:
            last = max(self.store["users"]) if self.store["users"] else None
            return _Result(_Row(scalar=last))

        # default no-op
        return _Result([])


class _Engine:
    def __init__(self, store):
        self.store = store

    def connect(self):
        return _Conn(self.store)

    def begin(self):
        return _Conn(self.store)


# ---------- Fixtures ----------
@pytest.fixture
def store():
    """Shared in-memory store for the fake DB."""
    return {"users": {}, "next_user_id": 1}

@pytest.fixture
def client(monkeypatch, store):
    # Route DB calls to the fake engine
    monkeypatch.setattr("server.get_engine", lambda _app: _Engine(store))

    # Make password hashing deterministic:
    # - store plain text on create
    # - compare equality on login
    monkeypatch.setattr("server.generate_password_hash", lambda plain: plain, raising=False)
    monkeypatch.setattr("server.check_password_hash", lambda hashed, plain: hashed == plain, raising=False)

    # If you also have wrappers, keep them consistent (harmless if not present)
    monkeypatch.setattr("server.hash_password", lambda plain: plain, raising=False)
    monkeypatch.setattr("server.verify_password", lambda plain, hashed: plain == hashed, raising=False)

    return app.test_client()


# ---------- Tests ----------
def test_create_user_happy(client):
    email = f"alice_{int(time.time())}@example.com"
    r = client.post(
        "/api/create-user",
        json={"login": "alice", "password": "secret123", "email": email},
    )
    assert r.status_code in (200, 201), r.data
    body = r.get_json()
    assert isinstance(body, dict)
    assert any(k in body for k in ("id", "user_id", "user")), body  # some identifier present


def test_login_success_after_create(client):
    email = f"bob_{int(time.time())}@example.com"
    password = "hunter2"

    r = client.post(
        "/api/create-user",
        json={"login": "bob", "password": password, "email": email},
    )
    assert r.status_code in (200, 201), r.data

    r = client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code in (200, 201), r.data
    body = r.get_json()
    assert isinstance(body, dict)
    assert "token" in body and body.get("token_type") == "bearer"


def test_login_failure_wrong_password(client):
    email = f"carol_{int(time.time())}@example.com"

    r = client.post(
        "/api/create-user",
        json={"login": "carol", "password": "right-pass", "email": email},
    )
    assert r.status_code in (200, 201), r.data

    r = client.post("/api/login", json={"email": email, "password": "wrong-pass"})
    assert r.status_code in (400, 401), r.data
    body = r.get_json()
    assert isinstance(body, dict)
    assert body.get("error")
