from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader

from signur.cms_content import is_attached_cms
from signur.models import AnalysisStatus, InputFormat


@dataclass(frozen=True)
class Detection:
    input_format: InputFormat
    media_type: str
    analysis_status: AnalysisStatus
    capabilities: list[str]
    warnings: list[str]


def detect_content(prefix: bytes, declared_media_type: str | None, path: Path) -> Detection:
    if prefix.startswith(b"%PDF-"):
        capabilities = ["cades"]
        try:
            with path.open("rb") as stream:
                reader = PdfFileReader(stream, strict=True)
                if int(reader.root["/Pages"]["/Count"]) > 0:
                    capabilities = ["graphic", "cades", "pades"]
        except (OSError, KeyError, TypeError, ValueError, PdfReadError):
            pass
        return Detection(
            InputFormat.PDF,
            "application/pdf",
            AnalysisStatus.PENDING,
            capabilities,
            ["pdf_analysis_pending"],
        )

    try:
        container = path.read_bytes()
    except OSError:
        container = b""
    if container and is_attached_cms(container):
        return Detection(
            InputFormat.CMS_ATTACHED,
            "application/pkcs7-mime",
            AnalysisStatus.PENDING,
            ["cades"],
            ["cms_analysis_pending"],
        )

    candidate = prefix.lstrip(b"\xef\xbb\xbf\x00\x09\x0a\x0d\x20")
    if candidate.startswith(b"<"):
        try:
            ElementTree.parse(path)
        except (ElementTree.ParseError, DefusedXmlException, ValueError):
            pass
        else:
            return Detection(
                InputFormat.XML,
                "application/xml",
                AnalysisStatus.COMPLETE,
                ["cades", "xades"],
                [],
            )

    media_type = declared_media_type or "application/octet-stream"
    if media_type in {"text/html", "image/svg+xml", "application/xhtml+xml"}:
        media_type = "application/octet-stream"
    return Detection(
        InputFormat.OPAQUE,
        media_type,
        AnalysisStatus.COMPLETE,
        ["cades"],
        [],
    )
