import io
from dataclasses import dataclass
from typing import Any

from PIL import Image
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.images import pil_image
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError, PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader


class GraphicPdfError(Exception):
    pass


@dataclass(frozen=True)
class GraphicPlacement:
    page: int
    x: float
    y: float
    width: float
    height: float
    layer_order: int
    png: bytes


def _inherited(page: generic.DictionaryObject, key: str) -> Any:
    current = page
    while True:
        try:
            return current[key]
        except KeyError:
            try:
                parent = current["/Parent"]
            except KeyError as exc:
                raise GraphicPdfError(f"La pagina PDF non contiene {key}.") from exc
            if not isinstance(parent, generic.DictionaryObject):
                raise GraphicPdfError("La gerarchia delle pagine PDF non è valida.") from None
            current = parent


def _page_geometry(writer: IncrementalPdfFileWriter, page_index: int) -> tuple[float, ...]:
    page_ref, _ = writer.find_page_for_modification(page_index)  # type: ignore[no-untyped-call]
    page = page_ref.get_object()
    try:
        box = _inherited(page, "/CropBox")
    except GraphicPdfError:
        box = _inherited(page, "/MediaBox")
    if not isinstance(box, generic.ArrayObject) or len(box) != 4:
        raise GraphicPdfError("Il rettangolo della pagina PDF non è valido.")
    llx, lly, urx, ury = (float(value) for value in box)
    width, height = urx - llx, ury - lly
    if width <= 0 or height <= 0:
        raise GraphicPdfError("Le dimensioni della pagina PDF non sono valide.")
    try:
        rotation = int(_inherited(page, "/Rotate")) % 360
    except GraphicPdfError:
        rotation = 0
    if rotation not in {0, 90, 180, 270}:
        raise GraphicPdfError("La rotazione della pagina PDF non è supportata.")
    return llx, lly, width, height, float(rotation)


def _matrix(geometry: tuple[float, ...], placement: GraphicPlacement) -> tuple[float, ...]:
    llx, lly, page_width, page_height, rotation_value = geometry
    rotation = int(rotation_value)
    display_width = page_width if rotation in {0, 180} else page_height
    display_height = page_height if rotation in {0, 180} else page_width
    visible_x = placement.x * display_width
    visible_y = (1 - placement.y - placement.height) * display_height
    width = placement.width * display_width
    height = placement.height * display_height
    if rotation == 0:
        return width, 0, 0, height, llx + visible_x, lly + visible_y
    if rotation == 90:
        return 0, width, -height, 0, llx + page_width - visible_y, lly + visible_x
    if rotation == 180:
        return (
            -width,
            0,
            0,
            -height,
            llx + page_width - visible_x,
            lly + page_height - visible_y,
        )
    return 0, -width, height, 0, llx + visible_y, lly + page_height - visible_x


def apply_graphics(original: bytes, placements: list[GraphicPlacement]) -> bytes:
    if not placements:
        raise GraphicPdfError("È richiesto almeno un posizionamento grafico.")
    input_stream = io.BytesIO(original)
    try:
        writer = IncrementalPdfFileWriter(input_stream, strict=True)
        page_count = int(writer.root["/Pages"]["/Count"])
        for item in sorted(placements, key=lambda value: value.layer_order):
            if not 1 <= item.page <= page_count:
                raise GraphicPdfError("Un posizionamento indica una pagina inesistente.")
            with Image.open(io.BytesIO(item.png)) as image:
                image.load()
                image_ref = pil_image(image.convert("RGBA"), writer)
            resource_name = pdf_name(f"/SignurGraphic{item.layer_order}")
            resources = generic.DictionaryObject(  # type: ignore[no-untyped-call]
                {
                    pdf_name("/XObject"): generic.DictionaryObject(  # type: ignore[no-untyped-call]
                        {resource_name: image_ref}
                    )
                }
            )
            a, b, c, d, e, f = _matrix(_page_geometry(writer, item.page - 1), item)
            command = f"q {a:g} {b:g} {c:g} {d:g} {e:g} {f:g} cm {resource_name} Do Q".encode()
            stream = writer.add_object(generic.StreamObject(stream_data=command))
            writer.add_stream_to_page(  # type: ignore[no-untyped-call]
                item.page - 1, stream, resources
            )
        output = io.BytesIO()
        writer.write(output)  # type: ignore[no-untyped-call]
        result = output.getvalue()
        PdfFileReader(io.BytesIO(result), strict=True)
        return result
    except GraphicPdfError:
        raise
    except (PdfError, PdfReadError, KeyError, TypeError, ValueError, OSError) as exc:
        raise GraphicPdfError("Il PDF grafico non può essere generato o verificato.") from exc
