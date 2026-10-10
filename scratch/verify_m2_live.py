"""Manual live verification script for Milestone M2."""

import sys
import httpx

BASE_URL = "http://127.0.0.1:8000"

print("==================================================")
print(" APIShield Milestone M2 Live Verification")
print("==================================================")

# 1. Verify Middleware & Health Endpoint
print("\n--- 1. SecurityGatewayMiddleware & Health Check ---")
r_health = httpx.get(f"{BASE_URL}/health")
assert r_health.status_code == 200, f"/health status failed: {r_health.status_code}"
assert r_health.json() == {"status": "ok"}, f"/health payload failed: {r_health.json()}"
assert "x-response-time-ms" in r_health.headers, "Missing X-Response-Time-Ms header"
duration = float(r_health.headers["x-response-time-ms"])
assert duration >= 0.0, f"Negative duration: {duration}"
print(f"SUCCESS: /health returned HTTP 200, X-Response-Time-Ms: {duration:.2f}ms")

# 2. Login as Alice and Admin
print("\n--- 2. Authenticating Test Users ---")
r_alice = httpx.post(f"{BASE_URL}/auth/login", json={"username": "alice", "password": "AliceSyntheticPass123!"})
assert r_alice.status_code == 200, f"Alice login failed: {r_alice.text}"
token_alice = r_alice.json()["access_token"]
headers_alice = {"Authorization": f"Bearer {token_alice}"}
print("SUCCESS: Alice (role: user) logged in.")

r_admin = httpx.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "AdminSyntheticPass123!"})
assert r_admin.status_code == 200, f"Admin login failed: {r_admin.text}"
token_admin = r_admin.json()["access_token"]
headers_admin = {"Authorization": f"Bearer {token_admin}"}
print("SUCCESS: Admin (role: admin) logged in.")

# 3. Defense Endpoints Access Control
print("\n--- 3. Defense Endpoints Access Control ---")
# Unauthenticated
r_unauth_def = httpx.get(f"{BASE_URL}/admin/defenses")
assert r_unauth_def.status_code == 401, f"Expected 401, got {r_unauth_def.status_code}"
print("SUCCESS: Unauthenticated GET /admin/defenses rejected with HTTP 401.")

# Alice (role: user)
r_alice_def = httpx.get(f"{BASE_URL}/admin/defenses", headers=headers_alice)
assert r_alice_def.status_code == 403, f"Expected 403, got {r_alice_def.status_code}"
print("SUCCESS: Alice GET /admin/defenses rejected with HTTP 403 (Admin access required).")

r_alice_patch = httpx.patch(f"{BASE_URL}/admin/defenses", json={"bola": True}, headers=headers_alice)
assert r_alice_patch.status_code == 403, f"Expected 403, got {r_alice_patch.status_code}"
print("SUCCESS: Alice PATCH /admin/defenses rejected with HTTP 403 (Admin access required).")

# Admin (role: admin)
r_admin_def = httpx.get(f"{BASE_URL}/admin/defenses", headers=headers_admin)
assert r_admin_def.status_code == 200, f"Expected 200, got {r_admin_def.status_code}"
defenses = r_admin_def.json()["defenses"]
print(f"SUCCESS: Admin GET /admin/defenses returned HTTP 200: {defenses}")
for flag, val in defenses.items():
    assert val is False, f"Flag {flag} expected False, got {val}"

# 4. PATCH Validation Checks
print("\n--- 4. PATCH /admin/defenses Validation Checks ---")
# Empty body -> 422
r_empty = httpx.patch(f"{BASE_URL}/admin/defenses", json={}, headers=headers_admin)
assert r_empty.status_code == 422, f"Expected 422 for empty body, got {r_empty.status_code}"
print("SUCCESS: Empty JSON object rejected with HTTP 422.")

# Unknown field -> 422
r_unknown = httpx.patch(f"{BASE_URL}/admin/defenses", json={"unknown_toggle": True}, headers=headers_admin)
assert r_unknown.status_code == 422, f"Expected 422 for unknown field, got {r_unknown.status_code}"
print("SUCCESS: Unknown field rejected with HTTP 422.")

# Non-boolean value -> 422
r_non_bool = httpx.patch(f"{BASE_URL}/admin/defenses", json={"bola": "not-bool"}, headers=headers_admin)
assert r_non_bool.status_code == 422, f"Expected 422 for non-boolean, got {r_non_bool.status_code}"
print("SUCCESS: Non-boolean value rejected with HTTP 422.")

# Valid update
r_patch_valid = httpx.patch(
    f"{BASE_URL}/admin/defenses",
    json={"bola": True, "auth_hardening": True},
    headers=headers_admin,
)
assert r_patch_valid.status_code == 200, f"Expected 200, got {r_patch_valid.status_code}"
updated_defenses = r_patch_valid.json()["defenses"]
assert updated_defenses["bola"] is True
assert updated_defenses["auth_hardening"] is True
assert updated_defenses["rate_limit"] is False
print(f"SUCCESS: Valid PATCH updated defenses: {updated_defenses}")

# 5. Security Events Endpoint
print("\n--- 5. Security Events Endpoints Access & Pagination ---")
# Unauthenticated
r_unauth_events = httpx.get(f"{BASE_URL}/admin/events")
assert r_unauth_events.status_code == 401, f"Expected 401, got {r_unauth_events.status_code}"
print("SUCCESS: Unauthenticated GET /admin/events rejected with HTTP 401.")

# Alice (role: user)
r_alice_events = httpx.get(f"{BASE_URL}/admin/events", headers=headers_alice)
assert r_alice_events.status_code == 403, f"Expected 403, got {r_alice_events.status_code}"
print("SUCCESS: Alice GET /admin/events rejected with HTTP 403.")

# Admin (role: admin)
r_admin_events = httpx.get(f"{BASE_URL}/admin/events", headers=headers_admin)
assert r_admin_events.status_code == 200, f"Expected 200, got {r_admin_events.status_code}"
events_data = r_admin_events.json()
print(f"SUCCESS: Admin GET /admin/events returned HTTP 200 (Total: {events_data['total']}, Limit: {events_data['limit']}).")

# Pagination bounds
r_bound_high = httpx.get(f"{BASE_URL}/admin/events?limit=101", headers=headers_admin)
assert r_bound_high.status_code == 422, f"Expected 422, got {r_bound_high.status_code}"
r_bound_low = httpx.get(f"{BASE_URL}/admin/events?limit=0", headers=headers_admin)
assert r_bound_low.status_code == 422, f"Expected 422, got {r_bound_low.status_code}"
r_bound_offset = httpx.get(f"{BASE_URL}/admin/events?offset=-1", headers=headers_admin)
assert r_bound_offset.status_code == 422, f"Expected 422, got {r_bound_offset.status_code}"
print("SUCCESS: Bounded pagination parameters enforced (limit 1-100, offset >= 0).")

# 6. Preserved M1 Security Invariants
print("\n--- 6. M1 Baseline Invariant Checks ---")
# Alice accesses own item (Item 1)
r_alice_item1 = httpx.get(f"{BASE_URL}/items/1", headers=headers_alice)
assert r_alice_item1.status_code == 200, f"Alice accessing Item 1 failed: {r_alice_item1.status_code}"
print("SUCCESS: Alice accessed own Item 1 (HTTP 200).")

# Alice accesses Bob's item (Item 3) -> 403 Forbidden even with bola toggle ON in M2
r_alice_item3 = httpx.get(f"{BASE_URL}/items/3", headers=headers_alice)
assert r_alice_item3.status_code == 403, f"Expected 403 Forbidden, got {r_alice_item3.status_code}"
print("SUCCESS: Alice accessing Bob's Item 3 strictly rejected (HTTP 403 Forbidden, M1 invariant intact).")

# Admin accesses Bob's item (Item 3) -> 200 OK (M1 baseline role rule)
r_admin_item3 = httpx.get(f"{BASE_URL}/items/3", headers=headers_admin)
assert r_admin_item3.status_code == 200, f"Admin accessing Item 3 failed: {r_admin_item3.status_code}"
print("SUCCESS: Admin accessed Item 3 (HTTP 200, M1 baseline intact).")

print("\n==================================================")
print(" ALL LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY!")
print("==================================================")
