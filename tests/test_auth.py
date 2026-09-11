def test_health_does_not_require_authentication(client):  # type: ignore[no-untyped-def]
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"


def test_first_user_is_admin_and_following_user_has_no_access(client, auth_headers):  # type: ignore[no-untyped-def]
    first = client.get("/api/v1/me", headers=auth_headers("first"))
    second = client.get("/api/v1/me", headers=auth_headers("second"))

    assert first.status_code == 200
    assert first.json()["role"] == "admin"
    assert second.status_code == 200
    assert second.json()["role"] == "no_access"
    assert second.json()["access_granted"] is False
    assert "amministratore" in second.json()["access_message"]

    blocked = client.get("/api/v1/documents", headers=auth_headers("second"))
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "access_pending"

    signer = client.get("/api/v1/signing-identity", headers=auth_headers("second"))
    assert signer.status_code == 403
    assert signer.json()["error"]["code"] == "access_pending"

    signature = client.post(
        "/api/v1/documents/00000000-0000-0000-0000-000000000001/signatures",
        headers={**auth_headers("second"), "Origin": "https://signur.test"},
        json={"mode": "cades"},
    )
    assert signature.status_code == 403
    assert signature.json()["error"]["code"] == "access_pending"

    job = client.get(
        "/api/v1/signature-jobs/00000000-0000-0000-0000-000000000001",
        headers=auth_headers("second"),
    )
    assert job.status_code == 403
    assert job.json()["error"]["code"] == "access_pending"

    result = client.get(
        "/api/v1/documents/00000000-0000-0000-0000-000000000001/result",
        headers=auth_headers("second"),
    )
    assert result.status_code == 403
    assert result.json()["error"]["code"] == "access_pending"

    graphics = client.get("/api/v1/graphic-signatures", headers=auth_headers("second"))
    assert graphics.status_code == 403
    assert graphics.json()["error"]["code"] == "access_pending"

    proxies = client.get("/api/v1/signing-proxies", headers=auth_headers("second"))
    assert proxies.status_code == 403
    assert proxies.json()["error"]["code"] == "access_pending"


def test_home_assets_are_public_but_do_not_contain_protected_data(client):  # type: ignore[no-untyped-def]
    home = client.get("/")
    script = client.get("/static/app.js")

    assert home.status_code == 200
    assert "Signur" in home.text
    assert script.status_code == 200
    assert "if (!profile.access_granted)" in script.text
    assert "new WebSocket" in script.text
    assert "loadAdminGraphics" in script.text
    assert "loadAdminProxies" in script.text
    assert "saveUserRole" in script.text
    assert "deleteDocument" in script.text
    assert "hasOtherEligibleUser" in script.text
    assert "availableProxies.length === 1" in script.text
    assert "legacyP7m" in script.text
    assert "signatureModeLabels" in script.text
    assert "cades_strategy" in script.text
    assert "confirm.hidden = false" in script.text
    assert "classList.toggle(\"compact\", !hasPdfPreview)" in script.text
    assert "startPlacementGesture" in script.text
    assert client.get("/static/pdf-preview.js").status_code == 200
    assert client.get("/static/vendor/pdfjs/LICENSE").status_code == 200
    assert client.get("/static/vendor/pdfjs/build/pdf.mjs").status_code == 200
    assert client.get("/static/vendor/pdfjs/build/pdf.worker.mjs").status_code == 200
    assert home.headers["content-security-policy"].startswith("default-src 'self'")


def test_unverified_forward_headers_are_rejected(client, auth_headers):  # type: ignore[no-untyped-def]
    headers = auth_headers("intruder")
    headers.pop("X-Signur-Auth")
    response = client.get("/api/v1/me", headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"
    assert response.headers["x-request-id"] == response.json()["error"]["request_id"]


def test_untrusted_gateway_is_rejected_before_authentication(client):  # type: ignore[no-untyped-def]
    from signur.config import get_settings

    settings = get_settings()
    previous = settings.trusted_gateway_ips
    settings.trusted_gateway_ips = ("192.0.2.10",)
    try:
        response = client.get("/api/v1/me")
    finally:
        settings.trusted_gateway_ips = previous

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "gateway_forbidden"


def test_cross_origin_mutation_is_rejected(client, auth_headers):  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/documents",
        headers={**auth_headers("owner"), "Origin": "https://evil.test"},
        files={"file": ("note.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "origin_forbidden"


def test_role_changes_and_self_demotion_guard(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    admin = client.get("/api/v1/me", headers=auth_headers("admin")).json()
    user = client.get("/api/v1/me", headers=auth_headers("user")).json()

    promoted = client.patch(
        f"/api/v1/admin/users/{user['id']}/role",
        headers=mutation_headers("admin"),
        json={"role": "admin"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "admin"

    self_demotion = client.patch(
        f"/api/v1/admin/users/{admin['id']}/role",
        headers=mutation_headers("admin"),
        json={"role": "user"},
    )
    assert self_demotion.status_code == 409
    assert self_demotion.json()["error"]["code"] == "self_demotion_forbidden"


def test_non_admin_cannot_list_users(client, auth_headers):  # type: ignore[no-untyped-def]
    admin = client.get("/api/v1/me", headers=auth_headers("admin")).json()
    user = client.get("/api/v1/me", headers=auth_headers("user")).json()
    promoted = client.patch(
        f"/api/v1/admin/users/{user['id']}/role",
        headers={**auth_headers("admin"), "Origin": "https://signur.test"},
        json={"role": "user"},
    )
    assert promoted.status_code == 200
    assert admin["role"] == "admin"
    response = client.get("/api/v1/admin/users", headers=auth_headers("user"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "admin_required"
