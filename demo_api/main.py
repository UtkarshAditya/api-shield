import sqlite3
import time
import traceback

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

SECRET = "dev-secret"  # FLAW: weak, hardcoded signing secret

app = FastAPI(title="Vulnerable Demo API")

# FLAW: wildcard CORS, and no security headers anywhere
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# In-memory database with 3 users
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


def current_user(creds: HTTPAuthorizationCredentials | None) -> dict:
    if creds is None:
        raise HTTPException(401, "Missing token")
    try:
        # FLAW: signature and expiry are NOT verified, so forged tokens work
        return jwt.decode(creds.credentials, options={"verify_signature": False})
    except Exception:
        raise HTTPException(401, "Bad token")


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/login")  # FLAW: no rate limiting, so brute force works
def login(body: LoginBody):
    row = db.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (body.username, body.password),
    ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    token = jwt.encode(
        {"sub": str(row["id"]), "role": row["role"], "exp": int(time.time()) + 3600},
        SECRET,
        algorithm="HS256",
    )
    return {"token": token}


@app.get("/search")
def search(q: str = ""):
    try:
        # FLAW: SQL injection, because the query is built by string concatenation
        rows = db.execute(
            f"SELECT id, username FROM users WHERE username LIKE '%{q}%'"
        ).fetchall()
        return {"results": [dict(r) for r in rows]}
    except Exception as e:
        # FLAW: verbose error leaks the stack trace
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "trace": traceback.format_exc()},
        )


@app.get("/users/{user_id}")
def get_user(user_id: int, creds=Depends(bearer)):
    current_user(creds)
    # FLAW: IDOR / BOLA. Nothing checks that the caller owns this user_id
    row = db.execute(
        "SELECT id, username, email, role FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    return dict(row)


@app.get("/profile")
def profile(creds=Depends(bearer)):
    user = current_user(creds)
    # FLAW: a secret key leaked in the response body
    return {"user_id": user["sub"], "api_key": "sk_live_51H8abc123DEMOKEY"}


@app.get("/admin/stats")
def admin_stats(creds=Depends(bearer)):
    # FLAW: the spec says auth is required, but the code never enforces it
    return {"users": 3, "revenue": 125000}


@app.get("/debug")
def debug():
    try:
        1 / 0
    except Exception:
        # FLAW: verbose error leaks the stack trace
        return JSONResponse(status_code=500, content={"trace": traceback.format_exc()})


@app.post("/comments")
def add_comment(body: dict):
    # FLAW: no input validation. Any JSON of any size or shape is accepted
    return {"saved": True, "echo": body}