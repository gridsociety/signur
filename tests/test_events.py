import pytest
from starlette.websockets import WebSocketDisconnect


def _websocket_headers(auth_headers, uid: str) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {**auth_headers(uid), "Origin": "https://signur.test"}


def test_websocket_reports_document_changes_without_refresh(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    with client.websocket_connect(
        "/api/v1/events", headers=_websocket_headers(auth_headers, "admin")
    ) as websocket:
        initial = websocket.receive_json()
        assert initial == {"type": "snapshot", "documents": [], "jobs": []}

        uploaded = client.post(
            "/api/v1/documents",
            headers=mutation_headers("admin"),
            files={"file": ("prova.txt", b"contenuto", "text/plain")},
        )
        assert uploaded.status_code == 201
        changed = websocket.receive_json()
        assert changed["type"] == "snapshot"
        assert changed["documents"][0]["id"] == uploaded.json()["id"]
        assert changed["documents"][0]["state"] == "to_sign"


def test_websocket_rejects_users_without_access(client, auth_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    client.get("/api/v1/me", headers=auth_headers("pending"))
    with pytest.raises(WebSocketDisconnect) as exc_info, client.websocket_connect(
        "/api/v1/events", headers=_websocket_headers(auth_headers, "pending")
    ):
        pass
    assert exc_info.value.code == 4403
