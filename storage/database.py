from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define the SQLite database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./sqlite.db"

# Create the SQLAlchemy engine to connect to the SQLite database
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

# Create a sessionmaker factory for database sessions
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Define the base class for models
Base = declarative_base()

# Dependency that will provide a new session for each request
def get_db():
    db = Session()  # Create a new database session
    try:
        yield db  # Yield the session for use in FastAPI dependency injection
    finally:
        db.close()  # Ensure the session is closed after the request is completed
