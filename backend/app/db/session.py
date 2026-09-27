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

from sqlalchemy import inspect, text

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_migrated = False

def auto_migrate_schema():
    """
    Idempotent schema auto-migration: ensures all columns defined in ORM models
    exist in the live database tables. Seamlessly handles pre-existing tables in
    PostgreSQL and SQLite without requiring external migration tooling.
    """
    global _migrated
    if _migrated:
        return
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        is_postgres = engine.dialect.name == "postgresql"

        # Expected new columns for crypto_assets added across Phase 1, Phase 2, and Phase 3:
        crypto_assets_cols = [
            ("source", "VARCHAR(50) DEFAULT 'tls' NOT NULL", "VARCHAR(50) DEFAULT 'tls'"),
            ("business_criticality", "VARCHAR(20) DEFAULT 'medium'", "VARCHAR(20) DEFAULT 'medium'"),
            ("data_lifetime", "VARCHAR(20) DEFAULT '1-3y'", "VARCHAR(20) DEFAULT '1-3y'"),
            ("pqc_recommendation", "TEXT", "TEXT"),
            ("algorithm", "VARCHAR(255)", "VARCHAR(255)"),
            ("usage_context", "VARCHAR(100)", "VARCHAR(100)"),
            ("confidence_score", "DOUBLE PRECISION", "FLOAT"),
            ("library", "VARCHAR(255)", "VARCHAR(255)"),
            ("file_path", "TEXT", "TEXT"),
            ("line_number", "INTEGER", "INTEGER"),
        ]

        if "crypto_assets" in tables:
            existing_cols = {c["name"] for c in inspector.get_columns("crypto_assets")}
            with engine.begin() as conn:
                for col_name, pg_def, sqlite_def in crypto_assets_cols:
                    if col_name not in existing_cols:
                        col_def = pg_def if is_postgres else sqlite_def
                        try:
                            if is_postgres:
                                conn.execute(text(f'ALTER TABLE crypto_assets ADD COLUMN IF NOT EXISTS "{col_name}" {col_def}'))
                            else:
                                conn.execute(text(f'ALTER TABLE crypto_assets ADD COLUMN "{col_name}" {col_def}'))
                            print(f"[Auto-Migrate] Added missing column '{col_name}' to crypto_assets")
                        except Exception as e:
                            print(f"[Auto-Migrate] Note: Could not add column '{col_name}': {e}")

                # Ensure default values are populated for any existing rows with NULL
                try:
                    conn.execute(text("UPDATE crypto_assets SET source = 'tls' WHERE source IS NULL OR source = ''"))
                    conn.execute(text("UPDATE crypto_assets SET business_criticality = 'medium' WHERE business_criticality IS NULL OR business_criticality = ''"))
                    conn.execute(text("UPDATE crypto_assets SET data_lifetime = '1-3y' WHERE data_lifetime IS NULL OR data_lifetime = ''"))
                except Exception:
                    pass

        _migrated = True
    except Exception as exc:
        print(f"[Auto-Migrate] Schema inspection warning: {exc}")

def init_db():
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        print(f"[Warning] DB init error (non-fatal): {exc}")
    auto_migrate_schema()

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
