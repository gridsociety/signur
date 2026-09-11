import asyncio
import io
from typing import cast

from PIL import Image
from pyhanko import stamp
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils import images as pdf_images
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import (
    AxisAlignment,
    InnerScaling,
    Margins,
    SimpleBoxLayoutRule,
)
from pyhanko.pdf_utils.misc import PdfError, PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import SignatureCoverageLevel, async_validate_cms_signature

from signur.graphics_pdf import GraphicPdfError, GraphicPlacement, placement_rect
from signur.proxy_signer import SIGNATURE_ALGORITHM_POLICY, ProxySigner
from signur.signing_proxy import SigningClient, SigningIdentity

FIELD_PREFIX = "Signature"


class PadesError(Exception):
    pass


def _appearance(png: bytes) -> stamp.StaticStampStyle:
    """Draw the PNG over the whole placement, transparent margins included."""
    with Image.open(io.BytesIO(png)) as image:
        image.load()
        background = pdf_images.PdfImage(image.convert("RGBA"))
    return stamp.StaticStampStyle(
        background=background,
        border_width=0,
        background_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MIN,
            y_align=AxisAlignment.ALIGN_MIN,
            margins=Margins(0, 0, 0, 0),
            inner_content_scaling=InnerScaling.STRETCH_FILL,
        ),
    )


def _empty_appearance(writer: IncrementalPdfFileWriter, field_name: str) -> None:
    """Give an invisible field the appearance the PDF specification asks for.

    There is nothing to draw inside a rectangle of no area, but an annotation is
    supposed to carry an appearance, and other tools write this empty form too.
    """
    for name, _value, reference in fields.enumerate_sig_fields(writer):
        if name != field_name:
            continue
        field = reference.get_object()
        form = generic.StreamObject(stream_data=b"")
        form[generic.pdf_name("/Type")] = generic.pdf_name("/XObject")
        form[generic.pdf_name("/Subtype")] = generic.pdf_name("/Form")
        corners = [generic.NumberObject(0) for _ in range(4)]  # type: ignore[no-untyped-call]
        form[generic.pdf_name("/BBox")] = generic.ArrayObject(corners)
        field[generic.pdf_name("/AP")] = generic.DictionaryObject(  # type: ignore[no-untyped-call]
            {generic.pdf_name("/N"): writer.add_object(form)}
        )
        writer.update_container(field)
        return


def _free_field_name(writer: IncrementalPdfFileWriter) -> str:
    """Signature1, Signature2, ...: the naming readers and other tools expect."""
    taken = {name for name, _value, _ref in fields.enumerate_sig_fields(writer)}
    index = 1
    while f"{FIELD_PREFIX}{index}" in taken:
        index += 1
    return f"{FIELD_PREFIX}{index}"


def _writer_for(original: bytes) -> IncrementalPdfFileWriter:
    """Read strictly, unless the only obstacle is the hybrid cross reference trick.

    Plenty of ordinary PDFs carry both a table and a stream for compatibility with
    older readers. Refusing them would make PAdES unusable on real documents.
    """
    writer = IncrementalPdfFileWriter(io.BytesIO(original), strict=True)
    if writer.prev.xrefs.hybrid_xrefs_present:
        return IncrementalPdfFileWriter(io.BytesIO(original), strict=False)
    return writer


async def build_pades_b_b_async(
    original: bytes,
    client: SigningClient,
    identity: SigningIdentity,
    placement: GraphicPlacement | None = None,
) -> bytes:
    try:
        writer = _writer_for(original)
        field_name = _free_field_name(writer)
        stamp_style = None
        if placement is None:
            spec = fields.SigFieldSpec(sig_field_name=field_name)
        else:
            rect = placement_rect(writer, placement)
            spec = fields.SigFieldSpec(
                sig_field_name=field_name,
                on_page=placement.page - 1,
                box=cast(tuple[int, int, int, int], tuple(round(value) for value in rect)),
            )
            stamp_style = _appearance(placement.png)
        fields.append_signature_field(writer, spec)
        if placement is None:
            _empty_appearance(writer, field_name)
        pdf_signer = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                field_name=field_name,
                subfilter=fields.SigSeedSubFilter.PADES,
                name=identity.display_name,
            ),
            signer=ProxySigner(client, identity),
            stamp_style=stamp_style,
        )
        output = await pdf_signer.async_sign_pdf(writer)
    except PadesError:
        raise
    except (
        GraphicPdfError,
        PdfError,
        PdfReadError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ) as exc:
        raise PadesError("Il PDF non può essere firmato in PAdES.") from exc
    return cast(bytes, output.getvalue())


def build_pades_b_b(
    original: bytes,
    client: SigningClient,
    identity: SigningIdentity,
    placement: GraphicPlacement | None = None,
) -> bytes:
    return asyncio.run(build_pades_b_b_async(original, client, identity, placement))


def _signature_count(pdf: bytes) -> int:
    return len(PdfFileReader(io.BytesIO(pdf), strict=True).embedded_signatures)


async def verify_pades_b_b_async(result: bytes, original: bytes) -> None:
    """Prove the result adds exactly one sound signature and keeps the original bytes."""
    try:
        if not result.startswith(original):
            raise PadesError("Il PDF firmato non conserva i byte originali.")
        reader = PdfFileReader(io.BytesIO(result), strict=True)
        signatures = reader.embedded_signatures
        if len(signatures) != _signature_count(original) + 1:
            raise PadesError("L'operazione non ha aggiunto esattamente una firma.")
        newest = signatures[-1]
        if newest.evaluate_signature_coverage() is not SignatureCoverageLevel.ENTIRE_FILE:
            raise PadesError("La nuova firma non copre l'intero documento.")
        status = await async_validate_cms_signature(
            newest.signed_data,
            raw_digest=newest.compute_digest(),
            algorithm_policy=SIGNATURE_ALGORITHM_POLICY,  # type: ignore[call-overload]
        )
        if not status.intact or not status.valid:
            raise PadesError("La verifica crittografica della firma PAdES è fallita.")
    except PadesError:
        raise
    except Exception as exc:
        raise PadesError("Il PDF firmato generato non è valido.") from exc


def verify_pades_b_b(result: bytes, original: bytes) -> None:
    asyncio.run(verify_pades_b_b_async(result, original))
