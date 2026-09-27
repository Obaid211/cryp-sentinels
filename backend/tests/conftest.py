"""
conftest.py — Pytest Configuration & Test Database Auto-initialization
=====================================================================
Ensures database tables are created and demo cryptographic assets
are seeded before tests execute, guaranteeing that tests run cleanly
in fresh CI environments (e.g. GitHub Actions Ubuntu runners) with
no existing sqlite database on disk.
"""

import pytest
from app.db.session import init_db, SessionLocal
from app.services.inventory import seed_demo_data
from app.models.models import Service, CryptoAsset


@pytest.fixture(scope="session", autouse=True)
def initialize_test_database():
    """Initializes tables and seeds baseline services and assets once per test session."""
    init_db()
    db = SessionLocal()
    try:
        if db.query(Service).count() == 0 or db.query(CryptoAsset).count() == 0:
            seed_demo_data(db)
    finally:
        db.close()
