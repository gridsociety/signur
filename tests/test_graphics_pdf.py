import io

import pytest
from PIL import Image
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

from signur.graphics_pdf import GraphicPlacement, _matrix, apply_graphics


def _pdf_bytes() -> bytes:
    writer = PdfFileWriter()
    stream = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(stream, (0, 0, 200, 300)))
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _transparent_png() -> bytes:
    output = io.BytesIO()
    Image.new("RGBA", (20, 10), (200, 30, 40, 128)).save(output, format="PNG")
    return output.getvalue()


def test_graphics_are_added_as_a_verified_incremental_pdf() -> None:
    original = _pdf_bytes()
    result = apply_graphics(
        original,
        [GraphicPlacement(1, 0.1, 0.2, 0.3, 0.1, 0, _transparent_png())],
    )

    assert result.startswith(original)
    reader = PdfFileReader(io.BytesIO(result), strict=True)
    page_ref, resources = reader.find_page_for_modification(0)  # type: ignore[no-untyped-call]
    assert page_ref.get_object()["/Contents"]
    assert "/SignurGraphic0" in resources.get_object()["/XObject"].get_object()


def test_normalized_top_left_coordinates_follow_page_rotation() -> None:
    placement = GraphicPlacement(1, 0.1, 0.2, 0.3, 0.1, 0, b"")
    assert _matrix((0, 0, 200, 300, 0), placement) == pytest.approx((60, 0, 0, 30, 20, 210))
    assert _matrix((0, 0, 200, 300, 90), placement) == pytest.approx((0, 90, -20, 0, 60, 30))
