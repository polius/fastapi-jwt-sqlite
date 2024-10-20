import jwt
import bcrypt
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from fastapi import Depends, APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

# Import necessary modules from the app
from app.storage import models
from app.storage.database import get_db
from app.config import (
    ACCESS_TOKEN_SECRET_KEY, 
    REFRESH_TOKEN_SECRET_KEY, 
    ALGORITHM, 
    ACCESS_TOKEN_EXPIRE_MINUTES, 
    REFRESH_TOKEN_EXPIRE_MINUTES
)

# Initialize FastAPI router
router = APIRouter(tags=["auth"])

# Set up OAuth2 password bearer for token-based authentication (used in login)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# curl -X POST "http://localhost:8000/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username=user&password=user"
@router.post("/login")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: Annotated[Session, Depends(get_db)]
) -> JSONResponse:

    # Retrieve user from the database using the provided username
    user = db.query(models.User).filter(models.User.username == form_data.username).first()

    # If the user does not exist or password doesn't match, raise an authentication error
    if not user or not bcrypt.checkpw(form_data.password.encode('utf-8'), user.password.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # If the user account is inactive, deny access
    if not user.is_active:
        raise HTTPException(status_code=401, detail="This account is disabled")

    # Generate an access token (short-lived) and refresh token (longer-lived)
    access_token = await create_token(
        data={"sub": user.username},  # Include username as subject
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),  # Token expiry time
        type='access',  # Token type: access
    )
    refresh_token = await create_token(
        data={"sub": user.username},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_MINUTES),
        type='refresh',  # Token type: refresh
    )

    # Create a JSON response with the access token
    response = JSONResponse({"access_token": access_token}, status_code=200)

    # Set the refresh token as a secure HTTP-only cookie (can't be accessed via JavaScript)
    response.set_cookie(key="refresh-token", value=refresh_token, httponly=True)

    # Return the response with access token and refresh token in the cookie
    return response


@router.post("/refresh")
async def refresh_token(
    request: Request, 
    db: Annotated[Session, Depends(get_db)]
):
    # Extract the refresh token from the cookie in the request
    cookies = request.cookies
    refresh_token = cookies.get('refresh-token')

    # If no refresh token is found in cookies, return an error
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    # Decode the refresh token to get the username (subject)
    username = await decode_token(refresh_token, type='refresh')

    # Retrieve the user from the database using the decoded username
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User does not exist")

    # Generate a new access token
    access_token = await create_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        type='access',
    )
    
    # Return a new access token in the response
    return JSONResponse({"access_token": access_token}, status_code=200)


####################
# Internal Methods #
####################

# Function to create a JWT token (both access and refresh tokens)
async def create_token(data: dict, expires_delta: timedelta, type: Annotated[str, 'access']):
    # Set the expiration time for the token
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = data.copy()
    to_encode.update({"exp": expire})  # Include expiration time in the payload

    # Encode the token based on the type (access or refresh)
    if type == 'refresh':
        return jwt.encode(to_encode, REFRESH_TOKEN_SECRET_KEY, algorithm=ALGORITHM)
    else:
        return jwt.encode(to_encode, ACCESS_TOKEN_SECRET_KEY, algorithm=ALGORITHM)

# Function to decode a JWT token and retrieve the username (subject)
async def decode_token(token: str, type: Annotated[str, 'access']) -> str | None:
    try:
        # Decode the token based on type (access or refresh) using the correct secret key
        if type == 'refresh':
            payload = jwt.decode(token, REFRESH_TOKEN_SECRET_KEY, algorithms=[ALGORITHM])
        else:
            payload = jwt.decode(token, ACCESS_TOKEN_SECRET_KEY, algorithms=[ALGORITHM])
        
        # Return the username (subject) from the token payload
        return payload.get("sub")

    # Catch any errors related to token decoding and raise an HTTP exception
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail=f"Invalid {type} token")


# Function to retrieve the current authenticated user using the access token
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> models.User | None:
    credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")

    try:
        # Decode the access token to retrieve the username
        payload = jwt.decode(token, ACCESS_TOKEN_SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.exceptions.InvalidTokenError:
        raise credentials_exception

    # Retrieve the user from the database using the decoded username
    user = db.query(models.User).filter(models.User.username == username).first()

    # If no user is found, raise an authentication error
    if not user:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=401, detail="This account has been disabled")

    # Return the authenticated user object
    return user
