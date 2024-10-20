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
router = APIRouter(prefix="/profile", tags=["profile"])

@router.get("/")
async def profile_get(
    user: Annotated[models.User, Depends(get_current_user)]
) -> JSONResponse:
    # Return a JSON response with the user information
    return JSONResponse({"username": user.username, "email": user.email}, status_code=200)


class ProfilePut(BaseModel):
    password: str | None = Field(None, min_length=5, description="Password must be at least 5 characters")
    email: EmailStr | None = None

@router.put("/")
async def profile_put(
    user_data: ProfilePut, 
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]
) -> JSONResponse:
    # Update fields if they are provided in the request
    if user_data.password:
        user.password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    if user_data.email:
        user.email = user_data.email

    # Commit fields to the database
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        if "users.email" in str(e.orig):
            raise HTTPException(status_code=400, detail="Email already exists")

    # Return message
    return JSONResponse({"message": "User updated successfully"}, status_code=200)
