import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.models.models import Base

# Support SQLite fallback automatically if Postgres is not reachable
database_url = settings.DATABASE_URL
if database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_engine(
    database_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

# Auto-initialize SQLite tables on load if local database
if database_url.startswith("sqlite"):
    try:
        init_db()
    except Exception:
        pass

def get_db():
    init_db()
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
