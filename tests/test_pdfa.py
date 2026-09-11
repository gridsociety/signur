from pdf_builder import pdfa_xmp, raw_pdf, stream_object

from signur.models import PdfaStatus
from signur.pdfa import check_pdfa

CONTENT = b"BT ET"


def _pdf(
    *,
    metadata: bytes | None = None,
    output_intent: bool = False,
    catalog_extra: str = "",
    page_extra: str = "",
    extra_objects: tuple[bytes, ...] = (),
) -> bytes:
    catalog = "/Type /Catalog /Pages 2 0 R"
    if metadata is not None:
        catalog += " /Metadata 5 0 R"
    if output_intent:
        catalog += (
            " /OutputIntents [ << /Type /OutputIntent /S /GTS_PDFA1 /DestOutputProfile 6 0 R >> ]"
        )
    catalog += " " + catalog_extra
    objects = [
        f"<< {catalog} >>".encode(),
        b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
        (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Contents 4 0 R {page_extra} >>"
        ).encode(),
        stream_object("", CONTENT),
        stream_object("/Type /Metadata /Subtype /XML", metadata or b"<x/>"),
        stream_object("/N 3", b"fake icc profile"),
        *extra_objects,
    ]
    return raw_pdf(objects)


def test_a_plain_pdf_is_not_pdfa_and_says_why() -> None:
    report = check_pdfa(_pdf())

    assert report.status is PdfaStatus.NON_CONFORMANT
    assert "missing_pdfa_identification" in report.violations
    assert "missing_output_intent" in report.violations


def test_a_pdf_that_declares_pdfa_properly_raises_no_violation() -> None:
    report = check_pdfa(_pdf(metadata=pdfa_xmp(), output_intent=True))

    assert report.violations == []
    assert report.status is PdfaStatus.CONFORMANT
    assert report.declared_part == "2B"


def test_the_declaration_is_read_in_its_attribute_form_too() -> None:
    report = check_pdfa(
        _pdf(metadata=pdfa_xmp(part="1", conformance="b", attribute_form=True), output_intent=True)
    )

    assert report.declared_part == "1B"
    assert report.violations == []


def test_metadata_without_a_pdfa_declaration_is_not_enough() -> None:
    report = check_pdfa(_pdf(metadata=b"<x:xmpmeta xmlns:x='adobe:ns:meta/'/>", output_intent=True))

    assert "missing_pdfa_identification" in report.violations


def _declared(**kwargs) -> bytes:  # type: ignore[no-untyped-def]
    return _pdf(metadata=pdfa_xmp(), output_intent=True, **kwargs)


def test_a_font_that_is_not_embedded_is_a_violation() -> None:
    report = check_pdfa(
        _declared(
            page_extra="/Resources << /Font << /F1 7 0 R >> >>",
            extra_objects=(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",),
        )
    )

    assert "font_not_embedded" in report.violations


def test_an_embedded_font_is_accepted() -> None:
    report = check_pdfa(
        _declared(
            page_extra="/Resources << /Font << /F1 7 0 R >> >>",
            extra_objects=(
                b"<< /Type /Font /Subtype /TrueType /BaseFont /Prova /FontDescriptor 8 0 R >>",
                b"<< /Type /FontDescriptor /FontName /Prova /FontFile2 4 0 R >>",
            ),
        )
    )

    assert report.violations == []


def test_javascript_is_a_violation() -> None:
    report = check_pdfa(
        _declared(catalog_extra="/OpenAction << /S /JavaScript /JS (app.alert 1) >>")
    )

    assert "javascript_present" in report.violations


def test_lzw_compression_is_a_violation() -> None:
    report = check_pdfa(
        _declared(
            extra_objects=(b"<< /Type /XObject /Subtype /Image /Filter /LZWDecode /Length 0 >>",)
        )
    )

    assert "lzw_compression" in report.violations


def test_transparency_is_a_violation_only_where_the_profile_forbids_it() -> None:
    page_extra = "/Group << /S /Transparency >>"

    part_one = check_pdfa(
        _pdf(metadata=pdfa_xmp(part="1"), output_intent=True, page_extra=page_extra)
    )
    part_two = check_pdfa(
        _pdf(metadata=pdfa_xmp(part="2"), output_intent=True, page_extra=page_extra)
    )

    assert "transparency_present" in part_one.violations
    assert part_two.violations == []


def test_attachments_are_a_violation_only_where_the_profile_forbids_them() -> None:
    catalog_extra = "/Names << /EmbeddedFiles << /Names [ ] >> >>"

    part_one = check_pdfa(
        _pdf(metadata=pdfa_xmp(part="1"), output_intent=True, catalog_extra=catalog_extra)
    )
    part_three = check_pdfa(
        _pdf(metadata=pdfa_xmp(part="3"), output_intent=True, catalog_extra=catalog_extra)
    )

    assert "embedded_files_present" in part_one.violations
    assert part_three.violations == []


def test_a_file_that_is_not_a_pdf_is_not_judged_at_all() -> None:
    report = check_pdfa(b"questo non e' un PDF")

    assert report.status is PdfaStatus.NOT_APPLICABLE
    assert report.violations == []


def test_a_pdf_we_cannot_read_is_never_called_non_pdf() -> None:
    report = check_pdfa(b"%PDF-1.7\ntroncato a meta")

    assert report.status is PdfaStatus.INDETERMINATE


def test_an_encrypted_pdf_cannot_be_judged() -> None:
    import io

    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

    writer = PdfFileWriter()
    stream = writer.add_object(generic.StreamObject(stream_data=b"% pagina"))
    writer.insert_page(PageObject(stream, (0, 0, 200, 300)))
    writer.encrypt("segreto")
    output = io.BytesIO()
    writer.write(output)

    report = check_pdfa(output.getvalue())

    assert report.status is PdfaStatus.INDETERMINATE
    assert "encrypted_pdf" in report.violations
