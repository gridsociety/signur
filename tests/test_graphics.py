import io

from PIL import Image
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter


def _png(*, transparent: bool = True) -> bytes:
    alpha = 128 if transparent else 255
    image = Image.new("RGBA", (12, 8), (30, 60, 90, alpha))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _pdf() -> bytes:
    writer = PdfFileWriter()
    stream = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(stream, (0, 0, 200, 300)))
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _create(client, headers, *, name: str = "Firma ufficio"):  # type: ignore[no-untyped-def]
    return client.post(
        "/api/v1/admin/graphic-signatures",
        headers=headers,
        data={"name": name, "description": "Timbro trasparente"},
        files={"image": ("firma.png", _png(), "image/png")},
    )


def test_admin_manages_versioned_graphics_and_user_downloads(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    admin = client.get("/api/v1/me", headers=auth_headers("admin")).json()
    user = client.get("/api/v1/me", headers=auth_headers("user")).json()
    client.patch(
        f"/api/v1/admin/users/{user['id']}/role",
        headers=mutation_headers("admin"),
        json={"role": "user"},
    )

    created = _create(client, mutation_headers("admin"))
    assert created.status_code == 201, created.text
    graphic = created.json()
    assert graphic["current_version_number"] == 1
    assert graphic["versions"][0]["width_pixels"] == 12

    listing = client.get("/api/v1/graphic-signatures", headers=auth_headers("user"))
    assert listing.status_code == 200
    assert listing.json()["total"] == 1

    versioned = client.post(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions",
        headers=mutation_headers("admin"),
        files={"image": ("firma-v2.png", _png(), "image/png")},
    )
    assert versioned.status_code == 201, versioned.text
    assert versioned.json()["current_version_number"] == 2

    downloaded = client.get(
        f"/api/v1/graphic-signatures/{graphic['id']}/versions/2/image",
        headers=auth_headers("user"),
    )
    assert downloaded.status_code == 200
    assert downloaded.content == _png()
    assert downloaded.headers["content-type"] == "image/png"

    deleted = client.delete(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions/1",
        headers=mutation_headers("admin"),
    )
    assert deleted.status_code == 204

    current = client.delete(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions/2",
        headers=mutation_headers("admin"),
    )
    assert current.status_code == 409
    assert current.json()["error"]["code"] == "current_graphic_version"
    assert admin["role"] == "admin"


def test_graphic_requires_real_transparency(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    response = client.post(
        "/api/v1/admin/graphic-signatures",
        headers=mutation_headers("admin"),
        data={"name": "Opaca"},
        files={"image": ("opaque.png", _png(transparent=False), "image/png")},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "graphic_without_transparency"


def test_admin_catalog_includes_inactive_graphics(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma archiviata").json()
    changed = client.patch(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}",
        headers=mutation_headers("admin"),
        json={"active": False},
    )
    assert changed.status_code == 200

    assert client.get("/api/v1/graphic-signatures", headers=auth_headers("admin")).json()[
        "total"
    ] == 0
    admin_catalog = client.get(
        "/api/v1/admin/graphic-signatures", headers=auth_headers("admin")
    )
    assert admin_catalog.status_code == 200
    assert admin_catalog.json()["items"][0]["name"] == "Firma archiviata"
    assert admin_catalog.json()["items"][0]["active"] is False


def test_ordinary_user_cannot_manage_graphics(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    admin = client.get("/api/v1/me", headers=auth_headers("admin")).json()
    user = client.get("/api/v1/me", headers=auth_headers("user")).json()
    client.patch(
        f"/api/v1/admin/users/{user['id']}/role",
        headers=mutation_headers("admin"),
        json={"role": "user"},
    )
    response = _create(client, mutation_headers("user"), name="Vietata")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "admin_required"
    assert admin["role"] == "admin"


def test_graphic_request_freezes_coordinates_and_artifact_version(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma congelata").json()
    version_id = graphic["versions"][0]["id"]
    uploaded = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("documento.pdf", _pdf(), "application/pdf")},
    )
    assert uploaded.status_code == 201
    assert "graphic" in uploaded.json()["capabilities"]

    response = client.post(
        f"/api/v1/documents/{uploaded.json()['id']}/signatures",
        headers=mutation_headers("admin"),
        json={
            "mode": "graphic",
            "placements": [
                {
                    "graphic_signature_version_id": version_id,
                    "page": 1,
                    "x": 0.1,
                    "y": 0.7,
                    "width": 0.25,
                    "height": 0.12,
                    "order": 0,
                }
            ],
        },
    )
    assert response.status_code == 202, response.text
    assert response.json()["placements"][0] == {
        "graphic_signature_version_id": version_id,
        "page": 1,
        "x": 0.1,
        "y": 0.7,
        "width": 0.25,
        "height": 0.12,
        "layer_order": 0,
    }
