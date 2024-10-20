import bcrypt
from fastapi import FastAPI

from app.storage.database import Base, Session, engine
import app.storage.models as models

from app.routers import auth
from app.routers.user import profile
from app.routers.admin import users

# Init FastAPI
app = FastAPI()

# Add routes
app.include_router(auth.router)
app.include_router(profile.router)
app.include_router(users.router)

# Add root route
@app.get("/")
async def root():
    return {"message": "Hello World!"}

# Initialize sqlite schema if does not exist
Base.metadata.create_all(bind=engine)

# Create a new session
with Session() as session:
    # Get number of users
    users_count = session.query(models.User).count()

    if users_count == 0:
        # Create default admin user
        admin_user = models.User(
            username="admin",
            password=bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            is_admin=True
        )

        # Add users to the session
        session.add(admin_user)

        # Commit the session to save the changes
        session.commit()
