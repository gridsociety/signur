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

    # Version 2 is now the only one left, so removing it takes the whole entry.
    current = client.delete(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions/2",
        headers=mutation_headers("admin"),
    )
    assert current.status_code == 204
    assert (
        client.get("/api/v1/admin/graphic-signatures", headers=auth_headers("admin")).json()[
            "total"
        ]
        == 0
    )
    assert admin["role"] == "admin"


def test_an_opaque_graphic_is_accepted(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    """Transparency suits a signature, but a plain image is the author's choice."""
    client.get("/api/v1/me", headers=auth_headers("admin"))

    response = client.post(
        "/api/v1/admin/graphic-signatures",
        headers=mutation_headers("admin"),
        data={"name": "Opaca"},
        files={"image": ("opaque.png", _png(transparent=False), "image/png")},
    )

    assert response.status_code == 201, response.text


def test_an_invisible_graphic_is_refused(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    """Nothing at all would be applied, so there is nothing to choose later."""
    import io

    from PIL import Image

    output = io.BytesIO()
    Image.new("RGBA", (12, 8), (0, 0, 0, 0)).save(output, format="PNG")
    client.get("/api/v1/me", headers=auth_headers("admin"))

    response = client.post(
        "/api/v1/admin/graphic-signatures",
        headers=mutation_headers("admin"),
        data={"name": "Invisibile"},
        files={"image": ("vuota.png", output.getvalue(), "image/png")},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "graphic_invisible"


def test_admin_catalog_includes_inactive_graphics(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma archiviata").json()
    changed = client.patch(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}",
        headers=mutation_headers("admin"),
        json={"active": False},
    )
    assert changed.status_code == 200

    assert (
        client.get("/api/v1/graphic-signatures", headers=auth_headers("admin")).json()["total"] == 0
    )
    admin_catalog = client.get("/api/v1/admin/graphic-signatures", headers=auth_headers("admin"))
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


def _placement(version_id: str, order: int) -> dict:  # type: ignore[type-arg]
    return {
        "graphic_signature_version_id": version_id,
        "page": 1,
        "x": 0.1,
        "y": 0.7,
        "width": 0.25,
        "height": 0.12,
        "order": order,
    }


def test_pades_is_available_without_a_graphic(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    uploaded = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("documento.pdf", _pdf(), "application/pdf")},
    )
    assert "pades" in uploaded.json()["capabilities"]

    response = client.post(
        f"/api/v1/documents/{uploaded.json()['id']}/signatures",
        headers=mutation_headers("admin"),
        json={"mode": "pades"},
    )

    assert response.status_code == 202, response.text
    assert response.json()["mode"] == "pades"


def test_pades_accepts_multiple_placements(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma PAdES").json()
    version_id = graphic["versions"][0]["id"]
    uploaded = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("documento.pdf", _pdf(), "application/pdf")},
    )
    document_id = uploaded.json()["id"]

    multiple = client.post(
        f"/api/v1/documents/{document_id}/signatures",
        headers=mutation_headers("admin"),
        json={
            "mode": "pades",
            "placements": [_placement(version_id, 0), _placement(version_id, 1)],
        },
    )
    assert multiple.status_code == 202, multiple.text
    assert [item["layer_order"] for item in multiple.json()["placements"]] == [0, 1]


def test_a_refused_plan_answers_with_a_readable_422(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma CAdES").json()
    uploaded = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("documento.pdf", _pdf(), "application/pdf")},
    )

    response = client.post(
        f"/api/v1/documents/{uploaded.json()['id']}/signatures",
        headers=mutation_headers("admin"),
        json={
            "mode": "cades",
            "placements": [_placement(graphic["versions"][0]["id"], 0)],
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
    assert "posizionamenti" in str(response.json()["error"]["details"])


def test_deleting_the_current_version_restores_the_previous_one(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma con storia").json()
    for _ in range(2):
        client.post(
            f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions",
            headers=mutation_headers("admin"),
            files={"image": ("firma.png", _png(), "image/png")},
        )

    removed = client.delete(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions/3",
        headers=mutation_headers("admin"),
    )

    assert removed.status_code == 204
    after = client.get("/api/v1/admin/graphic-signatures", headers=auth_headers("admin")).json()[
        "items"
    ][0]
    assert after["current_version_number"] == 2
    assert [version["version_number"] for version in after["versions"]] == [1, 2]


def test_a_version_a_document_uses_is_never_deleted(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Firma in uso").json()
    uploaded = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("documento.pdf", _pdf(), "application/pdf")},
    )
    client.post(
        f"/api/v1/documents/{uploaded.json()['id']}/signatures",
        headers=mutation_headers("admin"),
        json={"mode": "graphic", "placements": [_placement(graphic["versions"][0]["id"], 0)]},
    )

    refused = client.delete(
        f"/api/v1/admin/graphic-signatures/{graphic['id']}/versions/1",
        headers=mutation_headers("admin"),
    )

    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "graphic_version_referenced"


def test_the_catalogue_keeps_the_order_an_admin_gives_it(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    """The first graphic is the one offered by default, so its place matters."""
    client.get("/api/v1/me", headers=auth_headers("admin"))
    prima = _create(client, mutation_headers("admin"), name="Alfa").json()
    seconda = _create(client, mutation_headers("admin"), name="Zeta").json()

    reordered = client.put(
        "/api/v1/admin/graphic-signatures/order",
        headers=mutation_headers("admin"),
        json={"ids": [seconda["id"], prima["id"]]},
    )

    assert reordered.status_code == 200, reordered.text
    assert [item["name"] for item in reordered.json()["items"]] == ["Zeta", "Alfa"]
    admin_listing = client.get("/api/v1/admin/graphic-signatures", headers=auth_headers("admin"))
    assert [item["name"] for item in admin_listing.json()["items"]] == ["Zeta", "Alfa"]
    user_listing = client.get("/api/v1/graphic-signatures", headers=auth_headers("admin"))
    assert [item["name"] for item in user_listing.json()["items"]] == ["Zeta", "Alfa"]


def test_an_order_must_list_every_graphic_exactly_once(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    graphic = _create(client, mutation_headers("admin"), name="Sola").json()
    _create(client, mutation_headers("admin"), name="Altra")

    refused = client.put(
        "/api/v1/admin/graphic-signatures/order",
        headers=mutation_headers("admin"),
        json={"ids": [graphic["id"]]},
    )

    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "incomplete_graphic_order"
