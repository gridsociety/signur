import hashlib
import io
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import joinedload

from signur.database import get_session
from signur.models import AuditEvent, Document, InputFormat


def _upload(
    client, headers, name: str, content: bytes, media_type: str = "application/octet-stream"
):
    return client.post(
        "/api/v1/documents",
        headers=headers,
        files={"file": (name, content, media_type)},
    )


def _promote(client, admin_headers, user_id: str, role: str = "user"):
    return client.patch(
        f"/api/v1/admin/users/{user_id}/role",
        headers=admin_headers,
        json={"role": role},
    )


def _pdf() -> bytes:
    writer = PdfFileWriter()
    stream = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(stream, (0, 0, 200, 300)))
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _p7m(content: bytes) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signur preview test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(content)
        .add_signer(certificate, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )


def _audit_events(client, action: str):  # type: ignore[no-untyped-def]
    session_generator = client.app.dependency_overrides[get_session]()
    session = next(session_generator)
    try:
        return session.scalars(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.created_at)
        ).all()
    finally:
        session_generator.close()


def test_upload_generic_file_and_download_exact_bytes(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    content = b"arbitrary\x00office\xffbytes"
    response = _upload(client, mutation_headers("owner"), "../report.bin", content)

    assert response.status_code == 201
    document = response.json()
    assert document["original_name"] == "report.bin"
    assert document["input_format"] == "opaque"
    assert document["capabilities"] == ["cades"]
    assert document["sha256"] == hashlib.sha256(content).hexdigest()

    downloaded = client.get(
        f"/api/v1/documents/{document['id']}/original", headers=auth_headers("owner")
    )
    assert downloaded.status_code == 200
    assert downloaded.content == content
    assert downloaded.headers["content-type"] == "application/octet-stream"
    assert "attachment" in downloaded.headers["content-disposition"]
    download_events = _audit_events(client, "document.original_downloaded")
    assert len(download_events) == 1
    assert str(download_events[0].actor_user_id) == document["owner_user_id"]
    assert download_events[0].entity_id == document["id"]
    assert download_events[0].details["sha256"] == document["sha256"]


def test_xml_is_detected_from_content_not_extension(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    response = _upload(
        client,
        mutation_headers("owner"),
        "payload.dat",
        b'<?xml version="1.0"?><root><value>ok</value></root>',
        "application/octet-stream",
    )
    assert response.status_code == 201
    assert response.json()["input_format"] == "xml"
    assert response.json()["capabilities"] == ["cades", "xades"]


def test_pdf_specialized_modes_wait_for_analysis(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    response = _upload(
        client,
        mutation_headers("owner"),
        "not-trusted.txt",
        b"%PDF-1.7\nsynthetic",
        "text/plain",
    )
    assert response.status_code == 201
    assert response.json()["input_format"] == "pdf"
    assert response.json()["analysis_status"] == "pending"
    assert response.json()["capabilities"] == ["cades"]


def test_pdf_preview_is_inline_and_scoped(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    owner = client.get("/api/v1/me", headers=auth_headers("owner")).json()
    other = client.get("/api/v1/me", headers=auth_headers("other")).json()
    assert _promote(client, mutation_headers("admin"), owner["id"]).status_code == 200
    assert _promote(client, mutation_headers("admin"), other["id"]).status_code == 200
    content = _pdf()
    document = _upload(
        client, mutation_headers("owner"), "contratto.pdf", content, "application/pdf"
    ).json()

    preview = client.get(
        f"/api/v1/documents/{document['id']}/preview", headers=auth_headers("owner")
    )
    assert preview.status_code == 200
    assert preview.content == content
    assert preview.headers["content-type"] == "application/pdf"
    assert "inline" in preview.headers["content-disposition"]
    assert (
        client.get(
            f"/api/v1/documents/{document['id']}/preview", headers=auth_headers("other")
        ).status_code
        == 404
    )


def test_pdf_inside_nested_p7m_is_detected_and_previewed(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    content = _pdf()
    document = _upload(
        client,
        mutation_headers("owner"),
        "contratto.pdf.p7m.p7m",
        _p7m(_p7m(content)),
        "application/pkcs7-mime",
    ).json()

    assert document["input_format"] == "cms_attached"
    assert document["capabilities"] == ["cades"]

    queued = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("owner"),
        json={"mode": "cades", "cades_strategy": "parallel"},
    )
    assert queued.status_code == 202
    assert queued.json()["cades_strategy"] == "parallel"

    # Documents uploaded before CMS detection was introduced were stored as opaque.
    session_generator = client.app.dependency_overrides[get_session]()
    session = next(session_generator)
    try:
        stored = session.get(Document, UUID(document["id"]))
        assert stored is not None
        stored.input_format = InputFormat.OPAQUE
        session.commit()
    finally:
        session_generator.close()

    preview = client.get(
        f"/api/v1/documents/{document['id']}/preview", headers=auth_headers("owner")
    )
    assert preview.status_code == 200
    assert preview.headers["content-type"] == "application/pdf"
    assert preview.content == content


def test_non_pdf_p7m_has_no_preview(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    document = _upload(
        client,
        mutation_headers("owner"),
        "dati.txt.p7m",
        _p7m(b"testo"),
        "application/pkcs7-mime",
    ).json()
    response = client.get(
        f"/api/v1/documents/{document['id']}/preview", headers=auth_headers("owner")
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "preview_unavailable"


def test_document_scope_is_enforced_and_admin_can_see_all(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    owner = client.get("/api/v1/me", headers=auth_headers("owner")).json()
    other = client.get("/api/v1/me", headers=auth_headers("other")).json()
    assert _promote(client, mutation_headers("admin"), owner["id"]).status_code == 200
    assert _promote(client, mutation_headers("admin"), other["id"]).status_code == 200
    document = _upload(client, mutation_headers("owner"), "x.txt", b"secret", "text/plain").json()

    hidden = client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("other"))
    assert hidden.status_code == 404
    assert hidden.json()["error"]["code"] == "document_not_found"

    admin_view = client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("admin"))
    assert admin_view.status_code == 200
    assert admin_view.json()["owner"]["display_name"] == "Owner"


def test_owner_can_delete_unsigned_document(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    document = _upload(client, mutation_headers("owner"), "x.txt", b"temporary").json()
    deleted = client.delete(
        f"/api/v1/documents/{document['id']}", headers=mutation_headers("owner")
    )
    assert deleted.status_code == 204
    assert (
        client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("owner")).status_code
        == 404
    )


def test_document_delete_lock_only_targets_document_table():
    statement = (
        select(Document)
        .options(joinedload(Document.original_blob))
        .where(Document.id == UUID("00000000-0000-0000-0000-000000000001"))
        .with_for_update(of=Document)
    )

    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE OF documents" in sql


def test_empty_upload_is_rejected(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    response = _upload(client, mutation_headers("owner"), "empty.bin", b"")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "empty_upload"


def test_suspended_user_loses_visibility_without_losing_documents(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    owner = client.get("/api/v1/me", headers=auth_headers("owner")).json()
    assert _promote(client, mutation_headers("admin"), owner["id"]).status_code == 200
    document = _upload(client, mutation_headers("owner"), "kept.txt", b"kept").json()

    suspended = _promote(client, mutation_headers("admin"), owner["id"], "no_access")
    assert suspended.status_code == 200
    blocked = client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("owner"))
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "access_pending"

    admin_view = client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("admin"))
    assert admin_view.status_code == 200

    assert _promote(client, mutation_headers("admin"), owner["id"]).status_code == 200
    restored = client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("owner"))
    assert restored.status_code == 200


def test_admin_can_transfer_ownership_without_changing_original_uploader(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    admin = client.get("/api/v1/me", headers=auth_headers("admin")).json()
    owner = client.get("/api/v1/me", headers=auth_headers("owner")).json()
    new_owner = client.get("/api/v1/me", headers=auth_headers("new-owner")).json()
    assert _promote(client, mutation_headers("admin"), owner["id"]).status_code == 200
    assert _promote(client, mutation_headers("admin"), new_owner["id"]).status_code == 200
    document = _upload(client, mutation_headers("owner"), "delegato.txt", b"content").json()

    changed = client.patch(
        f"/api/v1/admin/documents/{document['id']}/owner",
        headers=mutation_headers("admin"),
        json={"owner_user_id": new_owner["id"]},
    )

    assert changed.status_code == 200
    body = changed.json()
    assert body["owner_user_id"] == new_owner["id"]
    assert body["owner"]["display_name"] == "New-Owner"
    assert body["uploaded_by_user_id"] == owner["id"]
    assert body["uploaded_by"]["display_name"] == "Owner"
    assert body["version"] == document["version"] + 1
    assert (
        client.get(f"/api/v1/documents/{document['id']}", headers=auth_headers("owner")).status_code
        == 404
    )
    assert (
        client.get(
            f"/api/v1/documents/{document['id']}", headers=auth_headers("new-owner")
        ).status_code
        == 200
    )
    events = _audit_events(client, "document.owner_changed")
    assert len(events) == 1
    assert str(events[0].actor_user_id) == admin["id"]
    assert events[0].details == {
        "from_user_id": owner["id"],
        "to_user_id": new_owner["id"],
    }


def test_document_owner_must_be_enabled_and_only_admin_can_transfer(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    owner = client.get("/api/v1/me", headers=auth_headers("owner")).json()
    pending = client.get("/api/v1/me", headers=auth_headers("pending")).json()
    assert _promote(client, mutation_headers("admin"), owner["id"]).status_code == 200
    document = _upload(client, mutation_headers("owner"), "x.txt", b"content").json()

    forbidden = client.patch(
        f"/api/v1/admin/documents/{document['id']}/owner",
        headers=mutation_headers("owner"),
        json={"owner_user_id": owner["id"]},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"] == "admin_required"

    ineligible = client.patch(
        f"/api/v1/admin/documents/{document['id']}/owner",
        headers=mutation_headers("admin"),
        json={"owner_user_id": pending["id"]},
    )
    assert ineligible.status_code == 422
    assert ineligible.json()["error"]["code"] == "owner_ineligible"


def test_xades_is_queued_with_the_chosen_packaging(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    document = _upload(
        client,
        mutation_headers("owner"),
        "fattura.xml",
        b'<?xml version="1.0"?><fattura><riga>uno</riga></fattura>',
        "application/xml",
    ).json()

    queued = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("owner"),
        json={"mode": "xades", "xades_packaging": "enveloping"},
    )

    assert queued.status_code == 202, queued.text
    assert queued.json()["mode"] == "xades"
    assert queued.json()["xades_packaging"] == "enveloping"


def test_xades_defaults_to_enveloped(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    document = _upload(
        client,
        mutation_headers("owner"),
        "fattura.xml",
        b'<?xml version="1.0"?><fattura><riga>uno</riga></fattura>',
        "application/xml",
    ).json()

    queued = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("owner"),
        json={"mode": "xades"},
    )

    assert queued.status_code == 202, queued.text
    assert queued.json()["xades_packaging"] == "enveloped"


def test_the_xml_packaging_is_refused_outside_xades(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))
    document = _upload(
        client,
        mutation_headers("owner"),
        "fattura.xml",
        b'<?xml version="1.0"?><fattura><riga>uno</riga></fattura>',
        "application/xml",
    ).json()

    refused = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("owner"),
        json={"mode": "cades", "xades_packaging": "enveloping"},
    )

    assert refused.status_code == 422, refused.text


def test_a_plain_pdf_is_reported_as_not_pdfa(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))

    document = _upload(
        client, mutation_headers("owner"), "contratto.pdf", _pdf(), "application/pdf"
    ).json()

    assert document["pdfa_status"] == "non_conformant"
    assert "missing_pdfa_identification" in document["pdfa_violations"]


def test_a_non_pdf_says_nothing_about_pdfa(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))

    document = _upload(
        client,
        mutation_headers("owner"),
        "fattura.xml",
        b'<?xml version="1.0"?><fattura/>',
        "application/xml",
    ).json()

    assert document["pdfa_status"] == "not_applicable"
    assert document["pdfa_violations"] == []


def test_the_pdf_inside_a_p7m_is_checked_too(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("owner"))

    document = _upload(
        client,
        mutation_headers("owner"),
        "contratto.pdf.p7m",
        _p7m(_pdf()),
        "application/pkcs7-mime",
    ).json()

    assert document["pdfa_status"] == "non_conformant"
