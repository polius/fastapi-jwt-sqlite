import bcrypt
from pydantic import BaseModel, Field, EmailStr
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# Import necessary modules from the app
from app.routers.auth import get_current_user
from app.storage.database import get_db
from app.storage import models

# Initialize the FastAPI router with a prefix for user-related endpoints
router = APIRouter(prefix="/admin/users", tags=["admin"])

@router.get("/{username}")
async def admin_users_get(
    username: str,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]
) -> JSONResponse:
    # Verify user is an admin
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Get the user
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="This user does not exist")
    return JSONResponse(
        {
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_admin": user.is_admin
        },
        status_code=200
    )

class UserPost(BaseModel):
    username: str
    password: str = Field(..., min_length=5, description="Password must be at least 5 characters")
    email: EmailStr | None
    is_active: bool | None = True
    is_admin: bool | None = False

@router.post("/")
async def admin_users_post(
    user_data: UserPost,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]
) -> JSONResponse:
    # Verify user is an admin
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Check if the username already exists
    user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash the password
    hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create new user
    new_user = models.User(
        username=user_data.username,
        password=hashed_password,
        email=user_data.email,
        is_active=user_data.is_active,
        is_admin=user_data.is_admin,
    )

    # Add the user to the database and commit the transaction
    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if "users.username" in str(e.orig):
            raise HTTPException(status_code=400, detail="Username already exists")
        elif "users.email" in str(e.orig):
            raise HTTPException(status_code=400, detail="Email already exists")

    # Return the response
    return JSONResponse({"message": "User created successfully"}, status_code=201)


class UserPut(BaseModel):
    username: str
    new_username: str | None = None
    password: str | None = Field(None, min_length=5, description="Password must be at least 5 characters")
    email: EmailStr | None = None
    is_active: bool | None = True
    is_admin: bool | None = False

@router.put("/{username}")
async def admin_users_put(
    user_data: UserPut,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]
) -> JSONResponse:
    # Verify user is an admin
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Retrieve the user from the database
    user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields if they are provided in the request
    if user_data.new_username:
        user.username = user_data.new_username
    if user_data.password:
        user.password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    if user_data.email:
        user.email = user_data.email
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    if user_data.is_admin is not None:
        user.is_admin = user_data.is_admin

    # Commit the changes to the database
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        if "users.username" in str(e.orig):
            raise HTTPException(status_code=400, detail="Username already exists")
        if "users.email" in str(e.orig):
            raise HTTPException(status_code=400, detail="Email already exists")

    # Return the response
    return JSONResponse({"message": "User updated successfully"}, status_code=200)

@router.delete("/{username}")
async def admin_users_delete(
    username: str,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]
) -> JSONResponse:
    # Verify user is an admin
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Retrieve the user from the database
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete the user from the database
    db.delete(user)
    db.commit()

    # Return the response
    return JSONResponse({"message": "User deleted successfully"}, status_code=200)
