"""Tests for database seeding and idempotence (Milestone M1-E)."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import verify_password
from backend.models.item import Item
from backend.models.user import User
from backend.seed import SEED_ITEMS, SEED_USERS, seed_database


def test_seed_database_creation_and_idempotence(db_session: Session) -> None:
    """Verify seeding creates expected users and items, and is strictly idempotent."""
    # Run seed once
    seed_database(db_session)

    # 1. Verify user counts and attributes
    users = db_session.query(User).all()
    assert len(users) == 3, f"Expected 3 users after first seed, got {len(users)}"
    user_names = {u.username for u in users}
    assert user_names == {"alice", "bob", "admin"}

    alice = db_session.query(User).filter(User.username == "alice").first()
    bob = db_session.query(User).filter(User.username == "bob").first()
    admin = db_session.query(User).filter(User.username == "admin").first()

    assert alice.role == "user"
    assert bob.role == "user"
    assert admin.role == "admin"

    # Verify password verification succeeds with synthetic credentials
    assert verify_password("AliceSyntheticPass123!", alice.hashed_password) is True
    assert verify_password("BobSyntheticPass123!", bob.hashed_password) is True
    assert verify_password("AdminSyntheticPass123!", admin.hashed_password) is True

    # 2. Verify item counts and ownership
    items = db_session.query(Item).all()
    assert len(items) == 4, f"Expected 4 items after first seed, got {len(items)}"

    alice_items = db_session.query(Item).filter(Item.owner_id == alice.id).all()
    bob_items = db_session.query(Item).filter(Item.owner_id == bob.id).all()
    assert len(alice_items) == 2, f"Expected Alice to own 2 items, got {len(alice_items)}"
    assert len(bob_items) == 2, f"Expected Bob to own 2 items, got {len(bob_items)}"

    # 3. IDEMPOTENCE TEST: Run seed a second time on the same database
    seed_database(db_session)

    users_after = db_session.query(User).all()
    items_after = db_session.query(Item).all()
    assert len(users_after) == 3, f"Expected 3 users after second seed, got {len(users_after)}"
    assert len(items_after) == 4, f"Expected 4 items after second seed, got {len(items_after)}"

    # Verify ownership relationships remain intact after re-seeding
    alice_items_after = db_session.query(Item).filter(Item.owner_id == alice.id).all()
    bob_items_after = db_session.query(Item).filter(Item.owner_id == bob.id).all()
    assert len(alice_items_after) == 2
    assert len(bob_items_after) == 2


def test_seeded_users_access_control(client: TestClient, db_session: Session) -> None:
    """Verify seeded users operate correctly with login and item authorization."""
    seed_database(db_session)

    # 1. Login Alice
    res_alice = client.post("/auth/login", json={"username": "alice", "password": "AliceSyntheticPass123!"})
    assert res_alice.status_code == 200
    token_alice = res_alice.json()["access_token"]
    headers_alice = {"Authorization": f"Bearer {token_alice}"}

    # 2. Login Bob
    res_bob = client.post("/auth/login", json={"username": "bob", "password": "BobSyntheticPass123!"})
    assert res_bob.status_code == 200
    token_bob = res_bob.json()["access_token"]
    headers_bob = {"Authorization": f"Bearer {token_bob}"}

    # 3. Login Admin
    res_admin = client.post("/auth/login", json={"username": "admin", "password": "AdminSyntheticPass123!"})
    assert res_admin.status_code == 200
    token_admin = res_admin.json()["access_token"]
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    alice_user = db_session.query(User).filter(User.username == "alice").first()
    bob_user = db_session.query(User).filter(User.username == "bob").first()
    alice_item = db_session.query(Item).filter(Item.owner_id == alice_user.id).first()
    bob_item = db_session.query(Item).filter(Item.owner_id == bob_user.id).first()

    # Alice accesses Alice's item -> 200 OK
    r1 = client.get(f"/items/{alice_item.id}", headers=headers_alice)
    assert r1.status_code == 200
    assert r1.json()["id"] == alice_item.id

    # Alice accesses Bob's item -> 403 Forbidden
    r2 = client.get(f"/items/{bob_item.id}", headers=headers_alice)
    assert r2.status_code == 403

    # Bob accesses Bob's item -> 200 OK
    r3 = client.get(f"/items/{bob_item.id}", headers=headers_bob)
    assert r3.status_code == 200
    assert r3.json()["id"] == bob_item.id

    # Bob accesses Alice's item -> 403 Forbidden
    r4 = client.get(f"/items/{alice_item.id}", headers=headers_bob)
    assert r4.status_code == 403

    # Admin accesses Alice's item -> 200 OK (baseline administrative access)
    r5 = client.get(f"/items/{alice_item.id}", headers=headers_admin)
    assert r5.status_code == 200

    # Admin accesses Bob's item -> 200 OK (baseline administrative access)
    r6 = client.get(f"/items/{bob_item.id}", headers=headers_admin)
    assert r6.status_code == 200
