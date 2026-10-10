"""Security event model for auditing and defense tracking."""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class SecurityEvent(Base):
    """SQLAlchemy model representing a security event in the APIShield platform.

    Persists metadata about detected or blocked actions, satisfying SPEC.md Section 7.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("action IN ('detected', 'blocked')", name="valid_event_action"),
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="valid_event_severity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    object_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    owasp_category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
