#!/usr/bin/env python3
"""Memorize Lab backend — auth, texts, scores, admin, sharing (stdlib only)."""

import json
import os
import re
import sqlite3
import hashlib
import secrets
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone, timedelta
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("ML_DB_PATH", os.path.join(ROOT, "memorize.db"))
STATIC_DIR = os.path.abspath(os.environ.get("ML_STATIC_DIR", os.path.dirname(ROOT)))
PORT = int(os.environ.get("PORT", "8765"))

# Simple rate limit: ip -> list of timestamps
_rate = defaultdict(list)
_rate_lock = threading.Lock()

def rate_ok(ip: str, limit: int = 30, window: int = 60) -> bool:
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate[ip] if now - t < window]
        if len(hits) >= limit:
            _rate[ip] = hits
            return False
        hits.append(now)
        _rate[ip] = hits
        return True

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000)
    return f"{salt}${h.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
        return secrets.compare_digest(hash_password(password, salt), stored)
    except Exception:
        return False

def clean_username(u: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "", u.strip())[:32]

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at REAL NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS texts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        word_count INTEGER NOT NULL,
        share_token TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        text_id INTEGER NOT NULL,
        mastered_chunks TEXT NOT NULL DEFAULT '[]',
        mastery_pct INTEGER NOT NULL DEFAULT 0,
        best_accuracy INTEGER NOT NULL DEFAULT 0,
        best_clarity INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0,
        last_score_at TEXT,
        next_review_at TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE(user_id, text_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(text_id) REFERENCES texts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS score_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        text_id INTEGER NOT NULL,
        accuracy INTEGER NOT NULL,
        coverage INTEGER NOT NULL,
        clarity INTEGER NOT NULL,
        mode TEXT NOT NULL DEFAULT 'voice',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(text_id) REFERENCES texts(id) ON DELETE CASCADE
    );
    """)
    # migrations
    def cols(table):
        return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    uc = cols("users")
    if "is_admin" not in uc:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    tc = cols("texts")
    if "share_token" not in tc:
        conn.execute("ALTER TABLE texts ADD COLUMN share_token TEXT")
    pc = cols("progress")
    if "next_review_at" not in pc:
        conn.execute("ALTER TABLE progress ADD COLUMN next_review_at TEXT")

    admin = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?,?,?,?,?)",
            ("admin", "admin@memorizelab.local", hash_password("admin123"), 1, now_iso()),
        )
    else:
        conn.execute("UPDATE users SET is_admin = 1 WHERE username = ?", ("admin",))
    conn.commit()
    conn.close()

def review_date_for_score(accuracy: int) -> str:
    """Spaced repetition: lower score = sooner review."""
    if accuracy >= 90:
        days = 7
    elif accuracy >= 75:
        days = 3
    elif accuracy >= 50:
        days = 1
    else:
        days = 0  # today
    d = datetime.now(timezone.utc) + timedelta(days=days)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {args[0] if args else fmt}")

    def client_ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def _cors(self):
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length))

    def _token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("ml_token="):
                return part[9:]
        return None

    def _user(self):
        token = self._token()
        if not token:
            return None
        conn = db()
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.expires_at > ?",
            (token, time.time()),
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            return self._api_get(path, parsed)
        if path in ("/", "/index.html"):
            path = "/memorize-lab.html"
        rel = path.lstrip("/")
        fpath = os.path.abspath(os.path.join(STATIC_DIR, rel))
        root = STATIC_DIR if STATIC_DIR.endswith(os.sep) else STATIC_DIR + os.sep
        if not (fpath == STATIC_DIR or fpath.startswith(root)):
            self.send_error(404)
            return
        if not os.path.isfile(fpath) and rel in ("memorize-lab.html",):
            for name in os.listdir(STATIC_DIR):
                if name.lower().endswith(".html") and "memorize" in name.lower():
                    fpath = os.path.join(STATIC_DIR, name)
                    break
        if not os.path.isfile(fpath):
            self.send_error(404)
            return
        ext = os.path.splitext(fpath)[1].lower()
        types = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript",
            ".css": "text/css",
            ".json": "application/json",
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }
        with open(fpath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", types.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            return self._api_post(path)
        self._json(404, {"error": "not found"})

    def do_PUT(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            return self._api_put(path)
        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            return self._api_delete(path)
        self._json(404, {"error": "not found"})

    def _api_get(self, path, parsed):
        if path == "/api/health":
            return self._json(200, {"ok": True, "service": "memorize-lab"})

        if path == "/api/me":
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            return self._json(200, {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "is_admin": bool(user.get("is_admin")),
            })

        # Public shared text
        m = re.match(r"^/api/share/([a-zA-Z0-9_-]+)$", path)
        if m:
            conn = db()
            t = conn.execute(
                "SELECT id, title, content, word_count FROM texts WHERE share_token = ?",
                (m.group(1),),
            ).fetchone()
            conn.close()
            if not t:
                return self._json(404, {"error": "share link not found"})
            return self._json(200, dict(t))

        if path == "/api/admin/users":
            user = self._user()
            if not user or not user.get("is_admin"):
                return self._json(403, {"error": "admin only"})
            conn = db()
            rows = conn.execute(
                "SELECT id, username, email, is_admin, created_at FROM users ORDER BY id"
            ).fetchall()
            conn.close()
            return self._json(200, {"users": [dict(r) for r in rows]})

        if path == "/api/admin/stats":
            user = self._user()
            if not user or not user.get("is_admin"):
                return self._json(403, {"error": "admin only"})
            conn = db()
            users_c = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
            admins = conn.execute("SELECT COUNT(*) c FROM users WHERE is_admin = 1").fetchone()["c"]
            texts = conn.execute("SELECT COUNT(*) c FROM texts").fetchone()["c"]
            scores = conn.execute("SELECT COUNT(*) c FROM score_history").fetchone()["c"]
            avg_acc = conn.execute("SELECT COALESCE(AVG(accuracy),0) a FROM score_history").fetchone()["a"]
            avg_clr = conn.execute("SELECT COALESCE(AVG(clarity),0) a FROM score_history").fetchone()["a"]
            active = conn.execute("SELECT COUNT(DISTINCT user_id) c FROM texts").fetchone()["c"]
            recent = conn.execute(
                """
                SELECT s.accuracy, s.clarity, s.mode, s.created_at, u.username, t.title
                FROM score_history s
                JOIN users u ON u.id = s.user_id
                JOIN texts t ON t.id = s.text_id
                ORDER BY s.created_at DESC LIMIT 20
                """
            ).fetchall()
            top = conn.execute(
                """
                SELECT u.username, COUNT(s.id) AS attempts,
                       COALESCE(ROUND(AVG(s.accuracy),1),0) AS avg_accuracy
                FROM users u
                LEFT JOIN score_history s ON s.user_id = u.id
                GROUP BY u.id ORDER BY attempts DESC LIMIT 10
                """
            ).fetchall()
            due = conn.execute(
                "SELECT COUNT(*) c FROM progress WHERE next_review_at IS NOT NULL AND next_review_at <= ?",
                (now_iso(),),
            ).fetchone()["c"]
            conn.close()
            return self._json(200, {
                "users": users_c,
                "admins": admins,
                "texts": texts,
                "scores": scores,
                "active_users": active,
                "avg_accuracy": round(float(avg_acc), 1),
                "avg_clarity": round(float(avg_clr), 1),
                "reviews_due": due,
                "recent_scores": [dict(r) for r in recent],
                "top_users": [dict(r) for r in top],
            })

        if path == "/api/texts":
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            conn = db()
            rows = conn.execute(
                """
                SELECT t.id, t.title, t.word_count, t.created_at, t.updated_at, t.share_token,
                       COALESCE(p.mastery_pct, 0) AS mastery_pct,
                       COALESCE(p.best_accuracy, 0) AS best_accuracy,
                       COALESCE(p.best_clarity, 0) AS best_clarity,
                       COALESCE(p.attempts, 0) AS attempts,
                       p.last_score_at, p.next_review_at
                FROM texts t
                LEFT JOIN progress p ON p.text_id = t.id AND p.user_id = t.user_id
                WHERE t.user_id = ?
                ORDER BY t.updated_at DESC
                """,
                (user["id"],),
            ).fetchall()
            conn.close()
            return self._json(200, {"texts": [dict(r) for r in rows]})

        m = re.match(r"^/api/texts/(\d+)$", path)
        if m:
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            tid = int(m.group(1))
            conn = db()
            t = conn.execute(
                "SELECT * FROM texts WHERE id = ? AND user_id = ?", (tid, user["id"])
            ).fetchone()
            if not t:
                conn.close()
                return self._json(404, {"error": "text not found"})
            p = conn.execute(
                "SELECT * FROM progress WHERE text_id = ? AND user_id = ?",
                (tid, user["id"]),
            ).fetchone()
            scores = conn.execute(
                "SELECT accuracy, coverage, clarity, mode, created_at FROM score_history "
                "WHERE text_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50",
                (tid, user["id"]),
            ).fetchall()
            conn.close()
            return self._json(200, {
                "text": dict(t),
                "progress": dict(p) if p else None,
                "scores": [dict(s) for s in scores],
            })

        self._json(404, {"error": "not found"})

    def _api_post(self, path):
        ip = self.client_ip()
        data = self._read_json()

        if path in ("/api/signup", "/api/login"):
            if not rate_ok(ip, limit=20, window=60):
                return self._json(429, {"error": "Too many attempts. Wait a minute and try again."})

        if path == "/api/signup":
            username = clean_username(data.get("username", ""))
            email = data.get("email", "").strip().lower()
            password = data.get("password", "")
            if len(username) < 3:
                return self._json(400, {"error": "Username must be at least 3 characters"})
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                return self._json(400, {"error": "Invalid email"})
            if len(password) < 6:
                return self._json(400, {"error": "Password must be at least 6 characters"})
            conn = db()
            try:
                cur = conn.execute(
                    "INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?,?,?,?,?)",
                    (username, email, hash_password(password), 0, now_iso()),
                )
                uid = cur.lastrowid
                token = secrets.token_urlsafe(32)
                conn.execute(
                    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
                    (token, uid, time.time() + 60 * 60 * 24 * 30),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return self._json(409, {"error": "Username or email already taken"})
            conn.close()
            return self._json(201, {
                "token": token,
                "user": {"id": uid, "username": username, "email": email, "is_admin": False},
            })

        if path == "/api/login":
            login = data.get("login", "").strip()
            password = data.get("password", "")
            conn = db()
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (login, login.lower()),
            ).fetchone()
            if not row or not verify_password(password, row["password_hash"]):
                conn.close()
                return self._json(401, {"error": "Invalid username/email or password"})
            token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
                (token, row["id"], time.time() + 60 * 60 * 24 * 30),
            )
            conn.commit()
            is_admin = bool(row["is_admin"]) if "is_admin" in row.keys() else False
            conn.close()
            return self._json(200, {
                "token": token,
                "user": {
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"],
                    "is_admin": is_admin,
                },
            })

        if path == "/api/logout":
            token = self._token()
            if token:
                conn = db()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
            return self._json(200, {"ok": True})

        if path == "/api/password":
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            old = data.get("old_password", "")
            new = data.get("new_password", "")
            if len(new) < 6:
                return self._json(400, {"error": "New password must be at least 6 characters"})
            conn = db()
            row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not row or not verify_password(old, row["password_hash"]):
                conn.close()
                return self._json(401, {"error": "Current password is wrong"})
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(new), user["id"]),
            )
            conn.commit()
            conn.close()
            return self._json(200, {"ok": True})

        if path == "/api/texts":
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            title = (data.get("title") or "Untitled").strip()[:120]
            content = (data.get("content") or "").strip()
            if not content:
                return self._json(400, {"error": "Content required"})
            words = len(content.split())
            ts = now_iso()
            conn = db()
            cur = conn.execute(
                "INSERT INTO texts (user_id, title, content, word_count, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (user["id"], title, content, words, ts, ts),
            )
            tid = cur.lastrowid
            conn.execute(
                "INSERT INTO progress (user_id, text_id, mastered_chunks, mastery_pct, updated_at) "
                "VALUES (?,?,?,?,?)",
                (user["id"], tid, "[]", 0, ts),
            )
            conn.commit()
            conn.close()
            return self._json(201, {"id": tid, "title": title, "word_count": words})

        if path == "/api/scores":
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            tid = data.get("text_id")
            accuracy = int(data.get("accuracy", 0))
            coverage = int(data.get("coverage", 0))
            clarity = int(data.get("clarity", 0))
            mode = data.get("mode", "voice")
            mastered = data.get("mastered_chunks")
            if not tid:
                return self._json(400, {"error": "text_id required"})
            ts = now_iso()
            next_rev = review_date_for_score(accuracy)
            conn = db()
            t = conn.execute(
                "SELECT id FROM texts WHERE id = ? AND user_id = ?", (tid, user["id"])
            ).fetchone()
            if not t:
                conn.close()
                return self._json(404, {"error": "text not found"})
            conn.execute(
                "INSERT INTO score_history (user_id, text_id, accuracy, coverage, clarity, mode, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (user["id"], tid, accuracy, coverage, clarity, mode, ts),
            )
            p = conn.execute(
                "SELECT * FROM progress WHERE user_id = ? AND text_id = ?",
                (user["id"], tid),
            ).fetchone()
            if p:
                best_acc = max(p["best_accuracy"], accuracy)
                best_clr = max(p["best_clarity"], clarity)
                attempts = p["attempts"] + 1
                chunks = p["mastered_chunks"]
                mastery = p["mastery_pct"]
                if mastered is not None:
                    chunks = json.dumps(mastered)
                conn.execute(
                    "UPDATE progress SET best_accuracy=?, best_clarity=?, attempts=?, "
                    "mastered_chunks=?, mastery_pct=?, last_score_at=?, next_review_at=?, updated_at=? "
                    "WHERE user_id=? AND text_id=?",
                    (best_acc, best_clr, attempts, chunks, mastery, ts, next_rev, ts, user["id"], tid),
                )
            conn.execute("UPDATE texts SET updated_at=? WHERE id=?", (ts, tid))
            conn.commit()
            conn.close()
            return self._json(201, {"ok": True, "next_review_at": next_rev})

        # Enable share link
        m = re.match(r"^/api/texts/(\d+)/share$", path)
        if m:
            user = self._user()
            if not user:
                return self._json(401, {"error": "not logged in"})
            tid = int(m.group(1))
            conn = db()
            t = conn.execute(
                "SELECT id, share_token FROM texts WHERE id = ? AND user_id = ?",
                (tid, user["id"]),
            ).fetchone()
            if not t:
                conn.close()
                return self._json(404, {"error": "text not found"})
            token = t["share_token"] or secrets.token_urlsafe(10)
            conn.execute("UPDATE texts SET share_token = ? WHERE id = ?", (token, tid))
            conn.commit()
            conn.close()
            return self._json(200, {"share_token": token})

        self._json(404, {"error": "not found"})

    def _api_put(self, path):
        user = self._user()
        if not user:
            return self._json(401, {"error": "not logged in"})
        data = self._read_json()

        m = re.match(r"^/api/texts/(\d+)/progress$", path)
        if m:
            tid = int(m.group(1))
            conn = db()
            t = conn.execute(
                "SELECT id FROM texts WHERE id = ? AND user_id = ?", (tid, user["id"])
            ).fetchone()
            if not t:
                conn.close()
                return self._json(404, {"error": "text not found"})
            chunks = data.get("mastered_chunks", [])
            mastery = int(data.get("mastery_pct", 0))
            ts = now_iso()
            conn.execute(
                """
                INSERT INTO progress (user_id, text_id, mastered_chunks, mastery_pct, updated_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(user_id, text_id) DO UPDATE SET
                    mastered_chunks=excluded.mastered_chunks,
                    mastery_pct=excluded.mastery_pct,
                    updated_at=excluded.updated_at
                """,
                (user["id"], tid, json.dumps(chunks), mastery, ts),
            )
            conn.execute("UPDATE texts SET updated_at=? WHERE id=?", (ts, tid))
            conn.commit()
            conn.close()
            return self._json(200, {"ok": True})

        m = re.match(r"^/api/texts/(\d+)$", path)
        if m:
            tid = int(m.group(1))
            conn = db()
            t = conn.execute(
                "SELECT id FROM texts WHERE id = ? AND user_id = ?", (tid, user["id"])
            ).fetchone()
            if not t:
                conn.close()
                return self._json(404, {"error": "text not found"})
            ts = now_iso()
            if data.get("title") is not None:
                conn.execute(
                    "UPDATE texts SET title=?, updated_at=? WHERE id=?",
                    (str(data["title"]).strip()[:120], ts, tid),
                )
            if data.get("content") is not None:
                content = data["content"]
                words = len(content.split())
                conn.execute(
                    "UPDATE texts SET content=?, word_count=?, updated_at=? WHERE id=?",
                    (content, words, ts, tid),
                )
            conn.commit()
            conn.close()
            return self._json(200, {"ok": True})

        self._json(404, {"error": "not found"})

    def _api_delete(self, path):
        user = self._user()
        if not user:
            return self._json(401, {"error": "not logged in"})

        m = re.match(r"^/api/texts/(\d+)$", path)
        if m:
            tid = int(m.group(1))
            conn = db()
            conn.execute("DELETE FROM score_history WHERE text_id=? AND user_id=?", (tid, user["id"]))
            conn.execute("DELETE FROM progress WHERE text_id=? AND user_id=?", (tid, user["id"]))
            cur = conn.execute("DELETE FROM texts WHERE id=? AND user_id=?", (tid, user["id"]))
            conn.commit()
            n = cur.rowcount
            conn.close()
            if not n:
                return self._json(404, {"error": "text not found"})
            return self._json(200, {"ok": True})

        m = re.match(r"^/api/admin/users/(\d+)$", path)
        if m:
            if not user.get("is_admin"):
                return self._json(403, {"error": "admin only"})
            uid = int(m.group(1))
            if uid == user["id"]:
                return self._json(400, {"error": "Cannot delete your own admin account"})
            conn = db()
            # cascade manually
            tids = [r["id"] for r in conn.execute("SELECT id FROM texts WHERE user_id=?", (uid,)).fetchall()]
            for tid in tids:
                conn.execute("DELETE FROM score_history WHERE text_id=?", (tid,))
                conn.execute("DELETE FROM progress WHERE text_id=?", (tid,))
            conn.execute("DELETE FROM score_history WHERE user_id=?", (uid,))
            conn.execute("DELETE FROM progress WHERE user_id=?", (uid,))
            conn.execute("DELETE FROM texts WHERE user_id=?", (uid,))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            cur = conn.execute("DELETE FROM users WHERE id=?", (uid,))
            conn.commit()
            n = cur.rowcount
            conn.close()
            if not n:
                return self._json(404, {"error": "user not found"})
            return self._json(200, {"ok": True})

        self._json(404, {"error": "not found"})


def main():
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Memorize Lab backend on http://0.0.0.0:{PORT}")
    print(f"DB: {DB_PATH}")
    print(f"Static: {STATIC_DIR}")
    server.serve_forever()


if __name__ == "__main__":
    main()
