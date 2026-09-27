import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.models.models import Base

# Support SQLite fallback automatically if Postgres is not reachable
database_url = settings.DATABASE_URL
if database_url.startswith("postgres://"):
    # Render and older platforms use postgres://; SQLAlchemy 2.0 requires postgresql://
    database_url = database_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif database_url.startswith("postgresql://") and not database_url.startswith("postgresql+"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg2://", 1)

if database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

try:
    engine = create_engine(
        database_url,
        connect_args=connect_args,
        pool_pre_ping=True
    )
except Exception as exc:
    print(f"[Warning] Failed to initialize engine with {database_url}: {exc}. Falling back to SQLite.")
    database_url = "sqlite:///./ecdat.db"
    connect_args = {"check_same_thread": False}
    engine = create_engine(
        database_url,
        connect_args=connect_args,
        pool_pre_ping=True
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        print(f"[Warning] DB init error (non-fatal): {exc}")

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
