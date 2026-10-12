"""Pytest fixtures and configuration for APIShield tests."""

from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.config import reset_lab_mode, set_lab_mode
from backend.database import Base, get_db
from backend.main import app
from backend.security.defenses import defense_manager

# StaticPool ensures that all threads and sessions share the exact same in-memory SQLite database
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(test_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def reset_defense_and_lab_state() -> Generator[None, None, None]:
    """Ensure defense manager and lab mode start and finish each test in default state."""
    defense_manager.reset()
    reset_lab_mode()
    yield
    defense_manager.reset()
    reset_lab_mode()


@pytest.fixture
def lab_mode_enabled() -> Generator[None, None, None]:
    """Temporarily enable lab mode for the duration of a test."""
    set_lab_mode(True)
    yield
    reset_lab_mode()


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Provide a clean, isolated database session per test function."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient wired to the test database session."""
    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client
    app.dependency_overrides.clear()
