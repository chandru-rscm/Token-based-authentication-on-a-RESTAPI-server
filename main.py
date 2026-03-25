from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt

from typing import Optional
import uvicorn

# ─── CONFIG ───────────────────────────────────────────────────────────────────
SECRET_KEY = "dcs-assignment-super-secret-key-2024"   # In production: use env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ─── APP SETUP ────────────────────────────────────────────────────────────────
app = FastAPI(title="JWT Auth REST API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Allow all origins for demo (laptop-to-laptop)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

bearer_scheme = HTTPBearer()

# Fake in-memory DB (no actual DB needed for demo)
fake_users_db: dict = {}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token error: {str(e)}")


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class MessageResponse(BaseModel):
    message: str


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {"status": "running", "message": "JWT Auth API is live"}


@app.post("/register", response_model=MessageResponse, tags=["Auth"])
def register(req: RegisterRequest):
    """Register a new user. Password is bcrypt-hashed before storing."""
    if req.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    fake_users_db[req.username] = {
        "username": req.username,
        "hashed_password": hash_password(req.password),
        "created_at": datetime.utcnow().isoformat()
    }
    return {"message": f"User '{req.username}' registered successfully"}


@app.post("/login", response_model=TokenResponse, tags=["Auth"])
def login(req: LoginRequest):
    """Login with credentials. Returns a signed JWT token valid for 30 minutes."""
    user = fake_users_db.get(req.username)
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    token = create_access_token(
        data={"sub": req.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


@app.get("/protected", tags=["Protected"])
def protected_route(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Access this only with a valid JWT in the Authorization header."""
    payload = verify_token(credentials.credentials)
    username = payload.get("sub")
    exp = payload.get("exp")
    expires_at = datetime.utcfromtimestamp(exp).isoformat()

    return {
        "message": f"Hello {username}! You accessed a protected resource.",
        "user": username,
        "token_expires_at": expires_at,
        "server_time": datetime.utcnow().isoformat()
    }


@app.get("/users", tags=["Debug"])
def list_users():
    """Debug route — shows registered users (without passwords) for demo."""
    return {
        "total_users": len(fake_users_db),
        "users": [
            {"username": u["username"], "created_at": u["created_at"]}
            for u in fake_users_db.values()
        ]
    }


# ─── RUN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # host="0.0.0.0" makes it accessible from other laptops on same network
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)