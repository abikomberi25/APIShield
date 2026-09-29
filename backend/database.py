"""Database configuration and session management for APIShield."""

from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# SQLite database file path (local-only, stored in project root)
DATABASE_URL = "sqlite:///./apishield.db"

# connect_args check_same_thread=False allows FastAPI multi-threaded requests to use the same connection
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# SQLite has foreign key constraints disabled by default for legacy compatibility.
# We explicitly hook into every new DBAPI connection to enforce foreign key referential integrity.
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all SQLAlchemy declarative models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and ensures it is closed on request completion."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
