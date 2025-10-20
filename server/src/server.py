import os
if os.getenv("CI"):
    pytest.skip("Skipping RMAP tests in CI environment", allow_module_level=True)

import io
import base64
import json
import hashlib
import datetime as dt
import time
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file, current_app, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle

from dotenv import load_dotenv
load_dotenv()

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method
from utils.signed_links import verify_token

# --- DB engine only (no Table metadata) ---
def db_url(app) -> str:
    return (
        f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
        f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
    )

def get_engine(app):
    eng = app.config.get("_ENGINE")
    if eng is None:
        eng = create_engine(db_url(app), pool_pre_ping=True, future=True)
        app.config["_ENGINE"] = eng
    return eng

# Rmap helper
def ensure_professor_doc(app) -> int:
    
    """
    Ensure the professor's document exists in the database.
    When TESTING=1, skip DB access and return a dummy ID instead.
    """
    # Skip DB logic entirely in test mode
    if os.environ.get("TESTING") == "1":
        print("[TEST MODE] Skipping ensure_professor_doc database initialization")
        return 1  # Dummy ID for tests

    pdf_path = app.config["STORAGE_DIR"] / "files" / "Group_10.pdf"

    if not pdf_path.exists():
        print(f"[WARN] Professor doc not found at {pdf_path}, skipping insert")
        return -1  

    file_bytes = pdf_path.read_bytes()
    sha256_hex = hashlib.sha256(file_bytes).hexdigest()
    file_size = pdf_path.stat().st_size

    with get_engine(app).begin() as conn:
        row = conn.execute(
            text("SELECT id FROM Documents WHERE name = :name LIMIT 1"),
            {"name": "Group_10.pdf"},
        ).first()
        if row:
            return int(row.id)

        conn.execute(
            text("""
                INSERT INTO Documents (name, path, ownerid, sha256, size)
                VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
            """),
            {
                "name": "Group_10.pdf",
                "path": str(pdf_path),
                "ownerid": 1,
                "sha256hex": sha256_hex,
                "size": file_size,
            },
        )
        new_id = conn.execute(text("SELECT LAST_INSERT_ID()")).scalar()
        return int(new_id)



metrics = PrometheusMetrics.for_app_factory(group_by='endpoint')

@metrics.counter(
    'rmap_requests_total',
    'RMAP requests by endpoint and client',
    labels={
        'endpoint': lambda: request.endpoint or 'none',
        'client_ip': lambda: request.remote_addr or 'unknown',
    },
)
def count_rmap_requests():
    """Count RMAP requests by endpoint and client."""
    pass


def create_app():
    app = Flask(__name__)

    # --- Enable Prometheus metrics only when not testing or CI ---
    if not (os.environ.get("TESTING") == "1" or os.environ.get("CI") == "true"):
        # Attach metrics exporter to this Flask app instance
        metrics.init_app(app)
        app.metrics = metrics
        app.metrics.info('tatou_app', 'Tatou watermarking service', version='1.0.0')
    else:
        print("[CI/TEST MODE] Skipping Prometheus metrics registration")


    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)


    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---
    
    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")
    
    @app.get("/healthz")
    def healthz():
        try:
            with get_engine(app).connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine(app).begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        # ny sanerad patch mot bugg hittad av fuzzer
        raw = file.filename or ""
        # Sanera filnamn och ta bara basnamnet
        fname = secure_filename(os.path.basename(raw))
        if not fname or fname in (".", ".."):
            fname = "upload.pdf"

        # Extra skydd: om rå-värdet innehåller traversal/separatorer -> 400
        if "/" in raw or "\\" in raw or ".." in raw:
            return jsonify({"error": "invalid filename"}), 400

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name

        try:
            file.save(stored_path)
        except Exception:
            # Fånga I/O-problem och svara 4xx istället för 500
            return jsonify({"error": "failed to save file"}), 400

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine(app).begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine(app).connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200



    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine(app).connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    
    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine(app).connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
    
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        

     # --- Allow RMAP "external" links to bypass token requirement ---
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT path, intended_for
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            app.logger.warning(f"DB lookup failed in get_version: {e}")
            row = None

        if row:
            path, intended_for = row[0], row[1]

            # if this link was created for RMAP exchange, allow public download
            import re   
            if intended_for and (
                intended_for.lower().strip() == "external" or
                re.match(r"^\d{1,3}(\.\d{1,3}){3}$", intended_for)
            ):

                from pathlib import Path
                fp = Path(path)
                if fp.exists():
                    app.logger.info(f"Serving external RMAP PDF {link} to {request.remote_addr}")
                    return send_file(
                        str(fp),
                        mimetype="application/pdf",
                        as_attachment=False,
                        download_name=f"{link}.pdf",
                    )
                else:
                    return jsonify({"error": "file missing on disk"}), 410
        # --- For all other documents, keep existing token-protected behaviour ---

        # --- Added: signed-link verification ---
        token = request.args.get("token")
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1]
        if not token:
            return jsonify({"error": "access token required"}), 401


        ok, v = verify_token(token)
        if not ok:
            return jsonify({"error": f"invalid token ({v})"}), 401
        if v != link:
            return jsonify({"error": "token does not match requested link"}), 401
      # --- End of added section ---
   					      
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        try:
            with get_engine(app).connect() as conn:
                query = "SELECT * FROM Documents WHERE id = " + doc_id
                row = conn.execute(text(query)).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine(app).begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200
        
        
    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    from flask import request, jsonify, current_app
    from werkzeug.exceptions import BadRequest

    ALLOWED_METHODS = {"text", "meta", "bits", "best"}
    ALLOWED_POS = {"tl","tr","bl","br","center"}

    def _as_str(x, maxlen=4096):
        return x if isinstance(x, str) and 0 < len(x) <= maxlen else None

    # POST /api/create-watermark or /api/create-watermark/<id>
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # --- dokument-id kan komma från path, query eller body ---
        # (men använd INTE interna HTTP-anrop här!)
        if document_id is None:
            # query eller body
            q_id = request.args.get("id") or request.args.get("documentid")
            if q_id is None and request.is_json:
                body0 = request.get_json(silent=True) or {}
                q_id = body0.get("id")
            try:
                document_id = int(q_id) if q_id is not None else None
            except (TypeError, ValueError):
                document_id = None
        if document_id is None:
            return jsonify({"error": "document id required"}), 400

        # --- säkert JSON-parsning ---
        try:
            payload = request.get_json(force=False, silent=True)
        except BadRequest:
            return jsonify({"error": "invalid json"}), 400
        if not isinstance(payload, dict):
            payload = {}

        # --- fält/validering ---
        method       = _as_str(payload.get("method"))
        intended_for = _as_str(payload.get("intended_for"))
        position     = _as_str(payload.get("position"))  # valfritt; kan vara None
        secret       = _as_str(payload.get("secret"))
        key          = _as_str(payload.get("key"))

        if method not in ALLOWED_METHODS:
            return jsonify({"error": "invalid method"}), 422
        if position is not None and position not in ALLOWED_POS:
            return jsonify({"error": "invalid position"}), 422
        if not intended_for:
            return jsonify({"error": "intended_for is required"}), 400
        if key is None or secret is None:
            return jsonify({"error": "key/secret must be non-empty strings"}), 422

        # --- lookup dokument & ägarskap ---
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": int(document_id)},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # --- säkert resolva filsökväg under STORAGE_DIR ---
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            # path utanför roten → behandla som ogiltig begäran (422) i stället för 500
            return jsonify({"error": "document path invalid"}), 422
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # --- kontrollera metodens applicerbarhet ---
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # --- applicera watermark ---
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except ValueError as e:
            return jsonify({"error": f"bad input: {e}"}), 422
        except Exception as e:
            current_app.logger.exception("watermarking failed")
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # --- skriv utfil ---
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # --- länktoken och INSERT av version ---
        link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()

        try:
            with get_engine(app).begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": int(document_id),
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": int(document_id),
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201
        
        
    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in wm_mod.METHODS.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
        storage_root = Path(app.config["STORAGE_DIR"])
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = plugins_dir / filename
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {safe}"}), 404

        # Unpickle the object (dill if available; else std pickle)
        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        # Accept: class object, or instance (we'll promote instance to its class)
        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        # Determine method name for registry
        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

        # Validate interface: either subclass of WatermarkingMethod or duck-typing
        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400
            
        # Register the class (not an instance) so you can instantiate as needed later
        WMUtils.METHODS[method_name] = cls()
        
        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201
        
    
    
    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
            
        return jsonify({"methods": methods, "count": len(methods)}), 200
        
    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400


# Change1
        # Optional: choose a specific version to read
        version_id = payload.get("version_id")
        link = payload.get("link")

        try:
            with get_engine(app).connect() as conn:
                # Enforce ownership on the base document
                doc_row = conn.execute(
                    text("""
                        SELECT d.id, d.name
                        FROM Documents d
                        WHERE d.id = :id AND d.ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
                if not doc_row:
                    return jsonify({"error": "document not found"}), 404

                # Decide which file to read:
                # 1) explicit version_id
                vrow = None
                if version_id is not None:
                    vrow = conn.execute(
                        text("""
                            SELECT v.id, v.link, v.path
                            FROM Versions v
                            JOIN Documents d ON d.id = v.documentid
                            WHERE v.id = :vid AND d.id = :did AND d.ownerid = :uid
                            LIMIT 1
                        """),
                        {"vid": int(version_id), "did": doc_id, "uid": int(g.user["id"])},
                    ).first()
                # 2) explicit link
                if vrow is None and link:
                    vrow = conn.execute(
                        text("""
                            SELECT v.id, v.link, v.path
                            FROM Versions v
                            JOIN Documents d ON d.id = v.documentid
                            WHERE v.link = :link AND d.id = :did AND d.ownerid = :uid
                            LIMIT 1
                        """),
                        {"link": str(link), "did": doc_id, "uid": int(g.user["id"])},
                    ).first()
                # 3) otherwise: latest version for this document
                if vrow is None:
                    vrow = conn.execute(
                        text("""
                            SELECT v.id, v.link, v.path
                            FROM Versions v
                            JOIN Documents d ON d.id = v.documentid
                            WHERE d.id = :did AND d.ownerid = :uid
                            ORDER BY v.id DESC
                            LIMIT 1
                        """),
                        {"did": doc_id, "uid": int(g.user["id"])},
                    ).first()

                if not vrow:
                    # No versions exist: fall back to the original document (likely no WM)
                    base_row = conn.execute(
                        text("""
                            SELECT d.path
                            FROM Documents d
                            WHERE d.id = :did AND d.ownerid = :uid
                            LIMIT 1
                        """),
                        {"did": doc_id, "uid": int(g.user["id"])},
                    ).first()
                    if not base_row:
                        return jsonify({"error": "document not found"}), 404
                    chosen_path = base_row.path
                else:
                    chosen_path = vrow.path
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(chosen_path)
# change 1
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410
        
        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 200
    

    # --- RMAP setup ---
    # Skip RMAP setup in CI/test environments
    if not (os.getenv("CI") or os.getenv("SKIP_RMAP")):
        from rmap.identity_manager import IdentityManager
        from rmap.rmap import RMAP

        def find_repo_root() -> Path:
            src_dir = Path(__file__).resolve().parent
            for parent in src_dir.parents:
                if (parent / "keys").exists():
                    return parent
            raise RuntimeError("Could not locate repo root with 'keys/' folder")

        REPO_ROOT = find_repo_root()

        KEYS_DIR = REPO_ROOT / "keys"
        PUBKEYS_DIR = KEYS_DIR / "pki"
        SERVER_PUB = KEYS_DIR / "server_pub.asc"
        SERVER_PRIV = KEYS_DIR / "server_priv.asc"

        identity_manager = IdentityManager(
            client_keys_dir=str(PUBKEYS_DIR),
            server_public_key_path=str(SERVER_PUB),
            server_private_key_path=str(SERVER_PRIV),
            server_private_key_passphrase="CLL"
        )
        app.rmap = RMAP(identity_manager)

        # --- Ensure professor doc exists ---
        if os.environ.get("TESTING", "0") == "1":
            # Skip DB in test mode
            app.config["PROFESSOR_DOC_ID"] = 1  # fake ID for tests
        else:
            prof_doc_id = ensure_professor_doc(app)
            app.config["PROFESSOR_DOC_ID"] = prof_doc_id


        @app.post("/api/rmap-initiate")
        def rmap_initiate():
            """
            Accept RMAP Message 1, return Response 1.
            """
            payload = request.get_json(silent=True) or {}
            if "payload" not in payload:
                return jsonify({"error": "payload is required"}), 400

            resp = current_app.rmap.handle_message1(payload)
            if "error" in resp:
                return jsonify(resp), 400

            return jsonify(resp), 200

        @app.post("/api/rmap-get-link")
        def rmap_get_link():
            """
            Accept RMAP Message 2, return Response 2 (hex result).
            Also generates a watermarked PDF linked to the session secret.
            """
            payload = request.get_json(silent=True) or {}
            if "payload" not in payload:
                return jsonify({"error": "payload is required"}), 400

            # addition to record external IP addresses
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        # Step 1: Let RMAP library handle Message 2
            resp = current_app.rmap.handle_message2(payload)
            if "error" in resp:
                return jsonify(resp), 400

            # Step 2: Extract session secret (32-hex NonceClient||NonceServer)
            session_secret = resp["result"]

            # -------------------------------
            # INSERT WATERMARKING HERE
            # -------------------------------
            # Input/output files
            pdf_in = Path(current_app.config["STORAGE_DIR"]) / "files" / "Group_10.pdf"
            pdf_out = Path(current_app.config["STORAGE_DIR"]) / "files" / f"{session_secret}.pdf"

            try:
                # Apply XMP-PerPage watermark
                wm_bytes = WMUtils.apply_watermark(
                    method="xmp-perpage",
                    pdf=str(pdf_in),
                    secret=session_secret,         # watermark = RMAP session secret
                    key="tatou_default_demo_key!", # must be >=16 chars
                    position=None                  # ignored in v1
                )

                # Save to disk
                with pdf_out.open("wb") as f:
                    f.write(wm_bytes)
            except Exception as e:
                return jsonify({"error": f"Failed to watermark with xmp-perpage: {e}"}), 500

            documentid = current_app.config["PROFESSOR_DOC_ID"]
            # -------------------------------
            # Insert DB entry so /get-version/<session_secret> can serve it
            # -------------------------------
            try:
                with get_engine(app).begin() as conn:
                    conn.execute(
                        text("""
                            INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                            VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                        """),
                        {
                            "documentid": documentid,  
                            "link": session_secret,
                            "intended_for": client_ip, #IP captured above
                            "secret": session_secret,
                            "method": "xmp-perpage",
                            "position": "",
                            "path": str(pdf_out),
                        },
                    )
            except Exception as e:
                return jsonify({"error": f"DB insert failed: {e}"}), 503

            # Step 3: Return the encrypted RMAP response
            return jsonify(resp), 200
    else:
        print("[CI/TEST MODE] Skipping RMAP setup to avoid key load and duplicate metrics")

    # --- Request path logging hook ---
    @app.after_request
    def log_request_path(response):
        if request.path != '/metrics':
            app.logger.info(f"{request.method} {request.path} -> {response.status_code}")
        return response

    return app


# WSGI entrypoint
app = create_app()


if __name__ == "__main__":
   port = int(os.environ.get("PORT", 5000))
   app.run(host="0.0.0.0", port=port)
