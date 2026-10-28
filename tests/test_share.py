"""Tests for the Shared Report Link feature.

These cover the security properties of the feature rather than only the happy
path: ownership enforcement on creation, server-side expiry, password
protection, and rejection of unknown tokens.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import main as main_module  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_state():
    Base.metadata.create_all(bind=engine)
    # The link store and the rate limiter are process-global, so clear both
    # between tests to keep them independent.
    main_module.SHARED_LINKS.clear()
    if hasattr(main_module, "_SHARE_HITS"):
        main_module._SHARE_HITS.clear()
    yield
    Base.metadata.drop_all(bind=engine)


def login(username="alice", email="alice@example.com", password="password123"):
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    return client.post(
        "/auth/login", json={"username": username, "password": password}
    ).json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def make_scan(token, title="Exposed storage bucket"):
    return client.post(
        "/scans",
        json={
            "title": title,
            "description": "Bucket allows public listing",
            "severity": "high",
            "affected_component": "storage/reports",
        },
        headers=headers(token),
    ).json()


def token_from(share_url):
    return share_url.rsplit("/", 1)[-1]


def test_create_share_link_returns_a_url():
    jwt = login()
    scan = make_scan(jwt)
    resp = client.post(f"/scans/{scan['id']}/share", json={}, headers=headers(jwt))
    assert resp.status_code == 200
    assert "/share/" in resp.json()["share_url"]
    # 32 random bytes, URL-safe base64 encoded, so at least 40 characters.
    assert len(token_from(resp.json()["share_url"])) >= 40


def test_tokens_are_unique_per_link():
    jwt = login()
    scan = make_scan(jwt)
    first = client.post(f"/scans/{scan['id']}/share", json={}, headers=headers(jwt)).json()
    second = client.post(f"/scans/{scan['id']}/share", json={}, headers=headers(jwt)).json()
    assert first["share_url"] != second["share_url"]


def test_create_share_requires_authentication():
    jwt = login()
    scan = make_scan(jwt)
    assert client.post(f"/scans/{scan['id']}/share", json={}).status_code in (401, 403)


def test_non_owner_cannot_share_another_users_scan():
    owner = login()
    scan = make_scan(owner)
    attacker = login("mallory", "mallory@example.com")
    resp = client.post(f"/scans/{scan['id']}/share", json={}, headers=headers(attacker))
    # 404 rather than 403, so the response does not confirm the scan exists.
    assert resp.status_code == 404


def test_public_read_needs_no_credentials():
    jwt = login()
    scan = make_scan(jwt)
    url = client.post(
        f"/scans/{scan['id']}/share", json={}, headers=headers(jwt)
    ).json()["share_url"]

    resp = client.get(f"/share/{token_from(url)}")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Exposed storage bucket"


def test_unknown_token_is_rejected():
    assert client.get("/share/" + "z" * 43).status_code == 404


def test_expired_link_is_rejected():
    jwt = login()
    scan = make_scan(jwt)
    url = client.post(
        f"/scans/{scan['id']}/share", json={}, headers=headers(jwt)
    ).json()["share_url"]
    tok = token_from(url)

    # Expiry is evaluated server-side, so backdating the stored value is enough.
    main_module.SHARED_LINKS[tok]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)
    assert client.get(f"/share/{tok}").status_code == 410


def test_link_expires_in_24_hours():
    jwt = login()
    scan = make_scan(jwt)
    url = client.post(
        f"/scans/{scan['id']}/share", json={}, headers=headers(jwt)
    ).json()["share_url"]

    expires_at = main_module.SHARED_LINKS[token_from(url)]["expires_at"]
    remaining = expires_at - datetime.now(timezone.utc)
    assert timedelta(hours=23, minutes=59) <= remaining <= timedelta(hours=24)


def test_password_protected_link_enforces_the_password():
    jwt = login()
    scan = make_scan(jwt)
    url = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "auditor-password"},
        headers=headers(jwt),
    ).json()["share_url"]
    tok = token_from(url)

    assert client.get(f"/share/{tok}").status_code == 401
    assert client.get(f"/share/{tok}?password=wrong-guess").status_code == 403

    ok = client.get(f"/share/{tok}?password=auditor-password")
    assert ok.status_code == 200
    assert ok.json()["title"] == "Exposed storage bucket"


def test_wrong_password_does_not_leak_scan_data():
    jwt = login()
    scan = make_scan(jwt)
    url = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "auditor-password"},
        headers=headers(jwt),
    ).json()["share_url"]

    body = client.get(f"/share/{token_from(url)}?password=wrong-guess").text
    assert "Exposed storage bucket" not in body
    assert "storage/reports" not in body


def test_password_is_stored_hashed_not_in_plaintext():
    jwt = login()
    scan = make_scan(jwt)
    url = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "auditor-password"},
        headers=headers(jwt),
    ).json()["share_url"]

    stored = main_module.SHARED_LINKS[token_from(url)]["password_hash"]
    assert stored is not None
    assert "auditor-password" not in stored
    assert stored.startswith("$2")


def test_public_reads_are_rate_limited():
    """Repeated guessing from one client is throttled."""
    statuses = {client.get("/share/" + "y" * 43).status_code for _ in range(25)}
    assert 429 in statuses
