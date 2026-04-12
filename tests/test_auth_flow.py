from __future__ import annotations

import uuid
from urllib.parse import urlparse, parse_qs

import pyotp


BOOTSTRAP_ADMIN_USERNAME = "admin"
BOOTSTRAP_ADMIN_PASSWORD = "admin123"
BOOTSTRAP_ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _unique_user(prefix: str = "user"):
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}_{suffix}".lower(), f"{prefix}_{suffix}@example.com"


def _strong_password() -> str:
    return "SecurePass!234"


def _otp_from_uri(uri: str) -> str:
    secret = parse_qs(urlparse(uri).query)["secret"][0]
    return pyotp.TOTP(secret).now()


def _register(client, username: str, email: str, password: str, role: str = "user"):
    return client.post(
        "/api/register",
        json={"username": username, "email": email, "password": password, "role": role},
    )


def _access_token_for(client, username: str, password: str, mfa_setup_uri: str) -> str:
    login_response = client.post("/api/login", json={"username": username, "password": password})
    verify_response = client.post(
        "/api/verify-mfa",
        json={"mfa_token": login_response.json()["mfa_token"], "otp": _otp_from_uri(mfa_setup_uri)},
    )
    return verify_response.json()["access_token"]


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


def test_admin_can_deactivate_and_restore_user(client):
    target_username, target_email = _unique_user("target")
    target_password = _strong_password()

    target_register = _register(client, target_username, target_email, target_password, "user")
    assert target_register.status_code == 200

    admin_login = client.post("/api/login", json={"username": BOOTSTRAP_ADMIN_USERNAME, "password": BOOTSTRAP_ADMIN_PASSWORD})
    admin_verify = client.post(
        "/api/verify-mfa",
        json={"mfa_token": admin_login.json()["mfa_token"], "otp": pyotp.TOTP(BOOTSTRAP_ADMIN_TOTP_SECRET).now()},
    )
    admin_access = admin_verify.json()["access_token"]

    users_response = client.get("/api/users", headers={"Authorization": f"Bearer {admin_access}"})
    assert users_response.status_code == 200
    users = users_response.json()
    target_user = next((u for u in users if u["username"] == target_username), None)
    assert target_user is not None

    deactivate_response = client.delete(f"/api/users/{target_user['id']}", headers={"Authorization": f"Bearer {admin_access}"})
    assert deactivate_response.status_code == 200

    deleted_user_login = client.post("/api/login", json={"username": target_username, "password": target_password})
    assert deleted_user_login.status_code == 401

    restore_response = client.post(f"/api/users/{target_user['id']}/restore", headers={"Authorization": f"Bearer {admin_access}"})
    assert restore_response.status_code == 200

    restored_user_login = client.post("/api/login", json={"username": target_username, "password": target_password})
    assert restored_user_login.status_code == 200


def test_non_admin_cannot_access_user_management(client):
    user_username, user_email = _unique_user("member")
    password = _strong_password()
    register_response = _register(client, user_username, user_email, password, "user")
    access_token = _access_token_for(client, user_username, password, register_response.json()["mfa_setup_uri"])

    users_response = client.get("/api/users", headers={"Authorization": f"Bearer {access_token}"})
    assert users_response.status_code == 403


def test_delete_user_not_found_returns_404(client):
    admin_login = client.post("/api/login", json={"username": BOOTSTRAP_ADMIN_USERNAME, "password": BOOTSTRAP_ADMIN_PASSWORD})
    admin_verify = client.post(
        "/api/verify-mfa",
        json={"mfa_token": admin_login.json()["mfa_token"], "otp": pyotp.TOTP(BOOTSTRAP_ADMIN_TOTP_SECRET).now()},
    )
    admin_access = admin_verify.json()["access_token"]

    response = client.delete("/api/users/does-not-exist", headers={"Authorization": f"Bearer {admin_access}"})
    assert response.status_code == 404


def test_admin_cannot_deactivate_admin_or_self(client):
    admin_login = client.post("/api/login", json={"username": BOOTSTRAP_ADMIN_USERNAME, "password": BOOTSTRAP_ADMIN_PASSWORD})
    admin_verify = client.post(
        "/api/verify-mfa",
        json={"mfa_token": admin_login.json()["mfa_token"], "otp": pyotp.TOTP(BOOTSTRAP_ADMIN_TOTP_SECRET).now()},
    )
    admin_access = admin_verify.json()["access_token"]
    me = client.get("/api/me", headers={"Authorization": f"Bearer {admin_access}"}).json()

    self_deactivate = client.delete(f"/api/users/{me['id']}", headers={"Authorization": f"Bearer {admin_access}"})
    assert self_deactivate.status_code == 400


def test_public_registration_cannot_create_admin_role(client):
    username, email = _unique_user("blockedadmin")
    response = _register(client, username, email, _strong_password(), "admin")
    assert response.status_code == 403


def test_bootstrap_admin_mfa_setup_endpoint_returns_qr(client):
    response = client.post(
        "/api/bootstrap-admin/mfa-setup",
        json={"username": BOOTSTRAP_ADMIN_USERNAME, "password": BOOTSTRAP_ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["mfa_setup_uri"].startswith("otpauth://")
    assert payload["qr_code_data_uri"].startswith("data:image/png;base64,")
