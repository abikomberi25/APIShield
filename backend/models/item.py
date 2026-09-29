"""Item model definition for SQLAlchemy ORM."""

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from backend.database import Base


class Item(Base):
    """Item entity representing a user-owned resource."""

    __tablename__ = "items"

    # Auto-incrementing integer primary key provides unique resource identification
    id = Column(Integer, primary_key=True, index=True)

    # Title of the resource
    title = Column(String, nullable=False)

    # Optional detailed description
    description = Column(String, nullable=True)

    # Foreign key referencing User.id; enforced by SQLite PRAGMA foreign_keys = ON
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Establish many-to-1 relationship: Many Items belong to one User
    owner = relationship("User", back_populates="items")
