"""User model definition for SQLAlchemy ORM."""

from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from backend.database import Base


class User(Base):
    """User entity representing an account in the system."""

    __tablename__ = "users"

    # Auto-incrementing integer primary key provides unique, immutable identity
    id = Column(Integer, primary_key=True, index=True)

    # Unique username for identification, indexed for fast lookups
    username = Column(String, unique=True, index=True, nullable=False)

    # Hashed password string (plaintext passwords must never be stored)
    hashed_password = Column(String, nullable=False)

    # Role designation: 'user' or 'admin'
    role = Column(String, default="user", nullable=False)

    # Establish 1-to-many relationship: One User has many Items
    items = relationship("Item", back_populates="owner", cascade="all, delete-orphan")
