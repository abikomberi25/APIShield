"""Database seeding script for APIShield.

Populates deterministic synthetic lab users and resources:
- alice (role: user) -> Item 1, Item 2
- bob (role: user) -> Item 3, Item 4
- admin (role: admin)

Idempotent: running multiple times does not duplicate records or cause errors.
Runnable via CLI: python -m backend.seed
"""

from typing import Any, Dict, List
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.auth.security import hash_password
from backend.database import Base, SessionLocal, engine
from backend.models.item import Item
from backend.models.user import User

# Deterministic synthetic test credentials
# (SPEC.md Safety Rule 3: strictly synthetic/fake lab data for local testing only)
SEED_USERS: List[Dict[str, Any]] = [
    {
        "username": "alice",
        "password": "AliceSyntheticPass123!",
        "role": "user",
    },
    {
        "username": "bob",
        "password": "BobSyntheticPass123!",
        "role": "user",
    },
    {
        "username": "admin",
        "password": "AdminSyntheticPass123!",
        "role": "admin",
    },
]

# Items mapped to username with synthetic internal properties for BOPLA evaluation
SEED_ITEMS: List[Dict[str, Any]] = [
    {
        "owner_username": "alice",
        "title": "Alice Private Document",
        "description": "Confidential notes for Alice",
        "internal_notes": "Internal audit: synthetic risk score 42/100",
        "is_confidential": False,
    },
    {
        "owner_username": "alice",
        "title": "Alice Project Plan",
        "description": "Q4 planning deliverables for Alice",
        "internal_notes": "Internal compliance: pending security review",
        "is_confidential": True,
    },
    {
        "owner_username": "bob",
        "title": "Bob Financial Report",
        "description": "Quarterly expense summary for Bob",
        "internal_notes": "Internal audit: budget reserve allocation",
        "is_confidential": True,
    },
    {
        "owner_username": "bob",
        "title": "Bob Strategy Memo",
        "description": "Internal strategy ideas for Bob",
        "internal_notes": "Internal risk: executive evaluation only",
        "is_confidential": False,
    },
]


def ensure_schema_compatibility(target_engine=engine) -> None:
    """Safely apply non-destructive SQLite schema additions to existing databases.

    Inspects PRAGMA table_info to ensure internal_notes and is_confidential columns
    exist on the items table, adding them via ALTER TABLE if missing.
    Preserves all existing users, items, foreign keys, and security event records.
    """
    Base.metadata.create_all(bind=target_engine)
    with target_engine.connect() as conn:
        result = conn.execute(text("PRAGMA table_info(items)")).fetchall()
        existing_cols = {row[1] for row in result}  # row[1] contains column name

        if "internal_notes" not in existing_cols:
            conn.execute(text("ALTER TABLE items ADD COLUMN internal_notes TEXT"))
        if "is_confidential" not in existing_cols:
            conn.execute(
                text("ALTER TABLE items ADD COLUMN is_confidential BOOLEAN")
            )
        conn.commit()


def seed_database(db: Session, target_engine=engine) -> None:
    """Idempotently seed deterministic synthetic users and items with schema compatibility."""
    # Ensure database tables exist and are schema-compatible
    ensure_schema_compatibility(target_engine)

    # 1. Seed Users (idempotent lookup by unique username)
    user_map = {}
    for user_data in SEED_USERS:
        user = db.query(User).filter(User.username == user_data["username"]).first()
        if not user:
            user = User(
                username=user_data["username"],
                hashed_password=hash_password(user_data["password"]),
                role=user_data["role"],
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        user_map[user.username] = user

    # 2. Seed Items (idempotent lookup by owner_id and title)
    for item_data in SEED_ITEMS:
        owner = user_map.get(item_data["owner_username"])
        if not owner:
            continue

        existing_item = (
            db.query(Item)
            .filter(
                Item.owner_id == owner.id,
                Item.title == item_data["title"],
            )
            .first()
        )
        if not existing_item:
            item = Item(
                title=item_data["title"],
                description=item_data["description"],
                owner_id=owner.id,
                internal_notes=item_data["internal_notes"],
                is_confidential=item_data["is_confidential"],
            )
            db.add(item)
            db.commit()
        else:
            # Backfill internal properties only if unpopulated (None).
            # Populated values (including False) are never overwritten to preserve legitimate customizations.
            updated = False
            if existing_item.internal_notes is None and item_data.get("internal_notes") is not None:
                existing_item.internal_notes = item_data["internal_notes"]
                updated = True
            if existing_item.is_confidential is None and item_data.get("is_confidential") is not None:
                existing_item.is_confidential = item_data["is_confidential"]
                updated = True
            if updated:
                db.commit()

    # Backfill any remaining unpopulated legacy items to safe non-null default (False)
    uninitialized_items = db.query(Item).filter(Item.is_confidential.is_(None)).all()
    if uninitialized_items:
        for item in uninitialized_items:
            item.is_confidential = False
        db.commit()



def main() -> None:
    """CLI entrypoint for explicit database seeding."""
    print("Seeding APIShield SQLite database with synthetic test data...")
    db = SessionLocal()
    try:
        seed_database(db)
        user_count = db.query(User).count()
        item_count = db.query(Item).count()
        print(f"Seeding complete: {user_count} users, {item_count} items in database.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
