import io
import re
import subprocess
from pathlib import Path

import pytest
from asn1crypto import cms  # type: ignore[import-untyped]
from fake_card import DirectSigningClient, authentication_key_usage
from pdf_builder import raw_pdf, stream_object
from PIL import Image
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

from signur.graphics_pdf import GraphicPlacement
from signur.pades import PadesError, build_pades_b_b, verify_pades_b_b


def _pdf_bytes(pages: int = 1, rotation: int | None = None) -> bytes:
    writer = PdfFileWriter()
    for _ in range(pages):
        stream = writer.add_object(generic.StreamObject(stream_data=b"% signur marker"))
        page = PageObject(stream, (0, 0, 200, 300))
        if rotation is not None:
            page[generic.pdf_name("/Rotate")] = generic.NumberObject(rotation)
        writer.insert_page(page)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _hybrid_pdf_bytes() -> bytes:
    """A PDF carrying the PDF 1.5 hybrid cross reference trick, as many real files do."""
    return raw_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Contents 4 0 R >>",
            stream_object("", b"% signur marker"),
        ],
        hybrid=True,
    )


def _transparent_png(width: int = 20, height: int = 10) -> bytes:
    output = io.BytesIO()
    Image.new("RGBA", (width, height), (200, 30, 40, 128)).save(output, format="PNG")
    return output.getvalue()


def _drawn_size(stream: str) -> tuple[float, float]:
    """Compose every `cm` matrix in the stream to get the size the image covers."""
    matrices = re.findall(
        r"(-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) -?[\d.]+ -?[\d.]+ cm", stream
    )
    width = height = 1.0
    for (
        a,
        _b,
        _c,
        d,
    ) in matrices:
        width *= float(a)
        height *= float(d)
    return width, height


def _detached_cms(signed: bytes) -> tuple[bytes, bytes]:
    """Pull the CMS object and the bytes it covers straight out of the PDF."""
    reader = PdfFileReader(io.BytesIO(signed), strict=True)
    signature = reader.embedded_signatures[0].sig_object
    byte_range = [int(value) for value in signature["/ByteRange"]]
    covered = b"".join(
        signed[start : start + length]
        for start, length in zip(byte_range[::2], byte_range[1::2], strict=True)
    )
    # /Contents is zero padded: parse the DER instead of trimming trailing bytes
    container = cms.ContentInfo.load(bytes(signature["/Contents"]))
    return bytes(container.dump()), covered


def _annotations(reader: PdfFileReader, page_index: int) -> list[generic.DictionaryObject]:
    page = reader.root["/Pages"]["/Kids"][page_index].get_object()
    return [item.get_object() for item in page.get("/Annots", [])]


def test_signs_a_pdf_without_an_appearance() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Signur PAdES test")

    result = build_pades_b_b(original, card, card.identity)

    assert result.startswith(original)
    reader = PdfFileReader(io.BytesIO(result), strict=True)
    assert len(reader.embedded_signatures) == 1


def test_the_appearance_lands_on_the_chosen_page_and_rectangle() -> None:
    original = _pdf_bytes(pages=2)
    card = DirectSigningClient("Signur PAdES test")
    placement = GraphicPlacement(
        page=2, x=0.1, y=0.2, width=0.3, height=0.1, layer_order=0, png=_transparent_png()
    )

    result = build_pades_b_b(original, card, card.identity, placement)

    reader = PdfFileReader(io.BytesIO(result), strict=True)
    assert _annotations(reader, 0) == []
    widgets = _annotations(reader, 1)
    assert len(widgets) == 1
    assert [float(value) for value in widgets[0]["/Rect"]] == pytest.approx([20, 210, 80, 240])
    assert widgets[0]["/AP"]["/N"] is not None


def test_the_appearance_fills_its_rectangle_without_a_border() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Signur PAdES test")
    placement = GraphicPlacement(
        page=1, x=0.1, y=0.2, width=0.3, height=0.1, layer_order=0, png=_transparent_png(40, 40)
    )

    result = build_pades_b_b(original, card, card.identity, placement)

    reader = PdfFileReader(io.BytesIO(result), strict=True)
    appearance = _annotations(reader, 0)[0]["/AP"]["/N"].get_object()
    stream = appearance.data.decode("latin-1")
    assert _drawn_size(stream) == pytest.approx((60, 30)), stream
    assert " re S" not in stream, stream


def test_signing_twice_adds_exactly_one_signature_each_time() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Signur PAdES test")

    once = build_pades_b_b(original, card, card.identity)
    twice = build_pades_b_b(once, card, card.identity)

    assert twice.startswith(once)
    assert len(PdfFileReader(io.BytesIO(once), strict=True).embedded_signatures) == 1
    assert len(PdfFileReader(io.BytesIO(twice), strict=True).embedded_signatures) == 2


def test_the_appearance_follows_the_page_rotation() -> None:
    original = _pdf_bytes(rotation=90)
    card = DirectSigningClient("Signur PAdES test")
    placement = GraphicPlacement(
        page=1, x=0.1, y=0.2, width=0.3, height=0.1, layer_order=0, png=_transparent_png()
    )

    result = build_pades_b_b(original, card, card.identity, placement)

    reader = PdfFileReader(io.BytesIO(result), strict=True)
    widget = _annotations(reader, 0)[0]
    assert [float(value) for value in widget["/Rect"]] == pytest.approx([40, 30, 60, 120])


def test_verification_accepts_a_signature_it_produced() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Signur PAdES test")

    verify_pades_b_b(build_pades_b_b(original, card, card.identity), original)


def test_verification_rejects_a_tampered_result() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Signur PAdES test")
    result = build_pades_b_b(original, card, card.identity)

    # a byte inside the signed revision, past the untouched original prefix
    tampered = result.replace(b"(Signature1)", b"(Signature7)", 1)

    assert tampered != result
    with pytest.raises(PadesError):
        verify_pades_b_b(tampered, original)


def test_the_signature_verifies_without_pyhanko(tmp_path: Path) -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Signur PAdES test")
    result = build_pades_b_b(original, card, card.identity)

    signature_der, signed_bytes = _detached_cms(result)
    signature_path = tmp_path / "signature.der"
    content_path = tmp_path / "content.bin"
    signature_path.write_bytes(signature_der)
    content_path.write_bytes(signed_bytes)

    completed = subprocess.run(
        [
            "openssl",
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-binary",
            "-noverify",
            "-no_check_time",
            "-in",
            str(signature_path),
            "-content",
            str(content_path),
            "-out",
            str(tmp_path / "out.bin"),
        ],
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr.decode()


def test_a_file_that_is_not_a_pdf_is_refused() -> None:
    card = DirectSigningClient("Signur PAdES test")

    with pytest.raises(PadesError):
        build_pades_b_b(b"questo non e' un PDF", card, card.identity)


def test_the_signature_fields_follow_the_usual_naming() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Mario Firmatario")

    once = build_pades_b_b(original, card, card.identity)
    twice = build_pades_b_b(once, card, card.identity)

    reader = PdfFileReader(io.BytesIO(twice), strict=True)
    names = [signature.field_name for signature in reader.embedded_signatures]
    assert names == ["Signature1", "Signature2"]


def test_the_signature_carries_the_certificate_holder_name() -> None:
    original = _pdf_bytes()
    card = DirectSigningClient("Mario Firmatario")

    result = build_pades_b_b(original, card, card.identity)

    signature = PdfFileReader(io.BytesIO(result), strict=True).embedded_signatures[0]
    assert str(signature.sig_object["/Name"]) == "Mario Firmatario"


def test_a_pdf_with_hybrid_cross_references_can_still_be_signed() -> None:
    original = _hybrid_pdf_bytes()
    card = DirectSigningClient("Mario Firmatario")

    result = build_pades_b_b(original, card, card.identity)

    assert result.startswith(original)
    verify_pades_b_b(result, original)


def test_a_cns_certificate_is_accepted_for_signing() -> None:
    """An authentication certificate may be used to sign: we warn, we do not refuse."""
    original = _pdf_bytes()
    card = DirectSigningClient("Mario Firmatario", authentication_key_usage())

    result = build_pades_b_b(original, card, card.identity)

    verify_pades_b_b(result, original)


def test_a_card_with_a_short_key_can_still_sign() -> None:
    """Cards in circulation still carry 1024 bit keys; signing with them is allowed."""
    original = _pdf_bytes()
    card = DirectSigningClient("Mario Firmatario", authentication_key_usage(), key_size=1024)

    result = build_pades_b_b(original, card, card.identity)

    verify_pades_b_b(result, original)
