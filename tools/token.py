from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone  # Add timezone import
from passlib.context import CryptContext
from typing import Optional, Union, Dict
from fastapi import FastAPI, HTTPException, Header
from tools.constant import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    JWT_SECRET_KEY,
    JWT_REFRESH_SECRET_KEY,
    ALGORITHM,
)

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Password hashing and verification
def get_password_hash(password: str) -> str:
    """Hash the password using bcrypt algorithm."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify the plain password against the stored hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

# Token creation
def create_access_token(data: dict) -> str:
    try:
        to_encode = data.copy()
        expire = datetime.now(tz=timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # Use timezone.utc
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        print("Error in create_access_token:", str(e))
        raise HTTPException(status_code=500, detail="Failed to create access token.")

def create_refresh_token(data: dict) -> str:
    """
    Generate a refresh token with a longer expiration time.
    """
    to_encode = data.copy()
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)  # Use timezone.utc
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Token validation
def validate_access_token(token: str) -> Union[Dict, None]:
    """
    Validate and decode an access token.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired access token.")

def validate_refresh_token(token: str) -> Union[Dict, None]:
    """
    Validate and decode a refresh token.
    """
    try:
        payload = jwt.decode(token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

# Extract Bearer token
def get_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    """
    Extract and validate the Bearer token from the Authorization header.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing.")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format.")
    return authorization[len("Bearer "):]
