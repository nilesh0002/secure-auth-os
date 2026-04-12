from __future__ import annotations

import uuid
from urllib.parse import urlparse, parse_qs

import pyotp


def _unique_user(prefix: str = "user"):
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}_{suffix}".lower(), f"{prefix}_{suffix}@example.com"


def _strong_password() -> str:
    return "SecurePass!234"


def _otp_from_uri(uri: str) -> str:
    secret = parse_qs(urlparse(uri).query)["secret"][0]
    return pyotp.TOTP(secret).now()


def test_register_login_mfa_and_me(client):
    username, email = _unique_user()
    password = _strong_password()

    register_response = client.post(
        "/api/register",
        json={"username": username, "email": email, "password": password, "role": "user"},
    )
    assert register_response.status_code == 200
    register_json = register_response.json()
    assert register_json["username"] == username
    assert register_json["mfa_setup_uri"]

    login_response = client.post(
        "/api/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200
    mfa_token = login_response.json()["mfa_token"]

    otp = _otp_from_uri(register_json["mfa_setup_uri"])
    verify_response = client.post(
        "/api/verify-mfa",
        json={"mfa_token": mfa_token, "otp": otp},
    )
    assert verify_response.status_code == 200
    tokens = verify_response.json()
    assert tokens["access_token"]
    assert tokens["refresh_token"]

    me_response = client.get("/api/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me_response.status_code == 200
    assert me_response.json()["username"] == username


def test_weak_password_rejected(client):
    username, email = _unique_user("weak")
    response = client.post(
        "/api/register",
        json={"username": username, "email": email, "password": "weakpass", "role": "user"},
    )
    assert response.status_code == 400


def test_user_cannot_access_admin_route(client):
    username, email = _unique_user("regular")
    password = _strong_password()

    register_response = client.post(
        "/api/register",
        json={"username": username, "email": email, "password": password, "role": "user"},
    )
    otp = _otp_from_uri(register_response.json()["mfa_setup_uri"])
    login_response = client.post("/api/login", json={"username": username, "password": password})
    verify_response = client.post(
        "/api/verify-mfa",
        json={"mfa_token": login_response.json()["mfa_token"], "otp": otp},
    )
    access_token = verify_response.json()["access_token"]

    admin_response = client.get("/api/admin/health", headers={"Authorization": f"Bearer {access_token}"})
    assert admin_response.status_code == 403


def test_change_password_and_reuse_block(client):
    username, email = _unique_user("changepw")
    original_password = _strong_password()
    new_password = "NewStrong!567"

    register_response = client.post(
        "/api/register",
        json={"username": username, "email": email, "password": original_password, "role": "user"},
    )
    otp = _otp_from_uri(register_response.json()["mfa_setup_uri"])

    login_response = client.post("/api/login", json={"username": username, "password": original_password})
    verify_response = client.post(
        "/api/verify-mfa",
        json={"mfa_token": login_response.json()["mfa_token"], "otp": otp},
    )
    access_token = verify_response.json()["access_token"]

    change_response = client.post(
        "/api/change-password",
        json={"current_password": original_password, "new_password": new_password},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert change_response.status_code == 200

    reuse_response = client.post(
        "/api/change-password",
        json={"current_password": new_password, "new_password": original_password},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert reuse_response.status_code == 400
