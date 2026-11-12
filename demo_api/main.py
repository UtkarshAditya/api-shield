import sqlite3
import time
import traceback

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 5


def build_app(mode: str = "vulnerable") -> FastAPI:
    """mode is 'vulnerable' or 'fixed'. Each call returns a fully independent
    app with its own database, secret, and rate-limit state -- nothing shared
    between the two modes, and nothing shared between test runs."""
    secret = "dev-secret" if mode == "vulnerable" else "a-much-longer-properly-random-secret-key-32bytes+"

    app = FastAPI(title="Vulnerable Demo API" if mode == "vulnerable" else "Hardened Demo API")

    if mode == "fixed":
        app.add_middleware(
            CORSMiddleware, allow_origins=["https://trusted-frontend.example.com"],
            allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"],
        )
    else:
        # FLAW: wildcard CORS, and no security headers anywhere
        app.add_middleware(
            CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
        )

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        if mode == "fixed":
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, "
        "email TEXT, role TEXT)"
    )
    db.executemany(
        "INSERT INTO users VALUES (?,?,?,?,?)",
        [
            (1, "alice", "alice123", "alice@example.com", "user"),
            (2, "bob", "bob123", "bob@example.com", "user"),
            (3, "admin", "admin123", "admin@example.com", "admin"),
        ],
    )
    db.commit()

    bearer = HTTPBearer(auto_error=False)
    login_attempts: dict[str, list[float]] = {}

    def current_user(creds: HTTPAuthorizationCredentials | None) -> dict:
        if creds is None:
            raise HTTPException(401, "Missing token")
        try:
            if mode == "fixed":
                return jwt.decode(creds.credentials, secret, algorithms=["HS256"])
            # FLAW: signature and expiry are NOT verified, so forged tokens work
            return jwt.decode(creds.credentials, options={"verify_signature": False})
        except Exception:
            raise HTTPException(401, "Bad token")

    class LoginBody(BaseModel):
        username: str
        password: str

    @app.post("/login")
    def login(body: LoginBody):
        if mode == "fixed":
            now = time.time()
            attempts = [t for t in login_attempts.get(body.username, []) if now - t < RATE_LIMIT_WINDOW]
            if len(attempts) >= RATE_LIMIT_MAX:
                raise HTTPException(429, "Too many login attempts. Try again later.")
            login_attempts[body.username] = attempts + [now]

        row = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (body.username, body.password),
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid credentials")
        token = jwt.encode(
            {"sub": str(row["id"]), "role": row["role"], "exp": int(time.time()) + 3600},
            secret,
            algorithm="HS256",
        )
        return {"token": token}

    @app.get("/search")
    def search(q: str = ""):
        try:
            if mode == "fixed":
                rows = db.execute(
                    "SELECT id, username FROM users WHERE username LIKE ?", (f"%{q}%",)
                ).fetchall()
            else:
                # FLAW: SQL injection, because the query is built by string concatenation
                rows = db.execute(
                    f"SELECT id, username FROM users WHERE username LIKE '%{q}%'"
                ).fetchall()
            return {"results": [dict(r) for r in rows]}
        except Exception as e:
            if mode == "fixed":
                raise HTTPException(500, "Internal server error")
            # FLAW: verbose error leaks the stack trace
            return JSONResponse(
                status_code=500,
                content={"error": str(e), "trace": traceback.format_exc()},
            )

    @app.get("/users/{user_id}")
    def get_user(user_id: int, creds=Depends(bearer)):
        user = current_user(creds)
        if mode == "fixed" and str(user_id) != str(user["sub"]) and user.get("role") != "admin":
            raise HTTPException(403, "You may only view your own profile")
        # FLAW (vulnerable mode): IDOR / BOLA, no ownership check at all
        row = db.execute(
            "SELECT id, username, email, role FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Not found")
        return dict(row)

    @app.get("/profile")
    def profile(creds=Depends(bearer)):
        user = current_user(creds)
        if mode == "fixed":
            return {"user_id": user["sub"]}
        # FLAW: a secret key leaked in the response body
        return {"user_id": user["sub"], "api_key": "sk_live_51H8abc123DEMOKEY"}

    @app.get("/admin/stats")
    def admin_stats(creds=Depends(bearer)):
        if mode == "fixed":
            user = current_user(creds)
            if user.get("role") != "admin":
                raise HTTPException(403, "Admins only")
            return {"users": 3, "revenue": 125000}
        # FLAW: the spec says auth is required, but the code never enforces it
        return {"users": 3, "revenue": 125000}

    @app.get("/debug")
    def debug():
        try:
            1 / 0
        except Exception:
            if mode == "fixed":
                raise HTTPException(500, "Internal server error")
            # FLAW: verbose error
            return JSONResponse(status_code=500, content={"trace": traceback.format_exc()})

    @app.post("/comments")
    def add_comment(body: dict):
        if mode == "fixed":
            text = body.get("text")
            if not isinstance(text, str) or len(text) > 500:
                raise HTTPException(422, "A 'text' field (string, max 500 chars) is required")
            return {"saved": True, "echo": body}
        # FLAW: no input validation. Any JSON of any size or shape is accepted
        return {"saved": True, "echo": body}

    return app


# Default export used by everything that currently does
# `from demo_api.main import app` or `uvicorn demo_api.main:app`
app = build_app("vulnerable")