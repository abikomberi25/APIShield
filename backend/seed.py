"""Database seeding script for APIShield.

Populates deterministic synthetic lab users and resources:
- alice (role: user) -> Item 1, Item 2
- bob (role: user) -> Item 3, Item 4
- admin (role: admin)

Idempotent: running multiple times does not duplicate records or cause errors.
Runnable via CLI: python -m backend.seed
"""

from typing import Any, Dict, List
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

# Items mapped to username
SEED_ITEMS: List[Dict[str, str]] = [
    {
        "owner_username": "alice",
        "title": "Alice Private Document",
        "description": "Confidential notes for Alice",
    },
    {
        "owner_username": "alice",
        "title": "Alice Project Plan",
        "description": "Q4 planning deliverables for Alice",
    },
    {
        "owner_username": "bob",
        "title": "Bob Financial Report",
        "description": "Quarterly expense summary for Bob",
    },
    {
        "owner_username": "bob",
        "title": "Bob Strategy Memo",
        "description": "Internal strategy ideas for Bob",
    },
]


def seed_database(db: Session) -> None:
    """Idempotently seed deterministic synthetic users and items."""
    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)

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
            )
            db.add(item)
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
