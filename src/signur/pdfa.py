"""Detect PDF/A violations we can prove, and admit when we cannot conclude.

Signur never claims a document *is* PDF/A: the interface only warns when a
violation is found, or when the check could not be completed. So this module
reports what it detects, never a certification.
"""

import io
from dataclasses import dataclass, field

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.misc import PdfError, PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader

from signur.models import PdfaStatus

PDFAID_NAMESPACE = "http://www.aiim.org/pdfa/ns/id/"
MAX_DICTIONARIES = 50_000


@dataclass(frozen=True)
class PdfaReport:
    status: PdfaStatus
    violations: list[str] = field(default_factory=list)
    declared_part: str | None = None


def _declared_part(metadata: bytes) -> str | None:
    """Read the PDF/A identification from the XMP packet, element or attribute form."""
    try:
        root = ElementTree.fromstring(metadata)
    except (ElementTree.ParseError, DefusedXmlException, ValueError):
        return None
    values = {}
    for field_name in ("part", "conformance"):
        element = root.find(f".//{{{PDFAID_NAMESPACE}}}{field_name}")
        value = element.text if element is not None else None
        if value is None:
            for node in root.iter():
                value = node.get(f"{{{PDFAID_NAMESPACE}}}{field_name}")
                if value is not None:
                    break
        values[field_name] = (value or "").strip()
    if not values["part"]:
        return None
    return values["part"] + values["conformance"].upper()


def _dictionaries(reader: PdfFileReader) -> list[generic.DictionaryObject]:
    """Every dictionary in the file, nested ones included, each visited once."""
    found: list[generic.DictionaryObject] = []
    pending: list[object] = []
    for revision in range(reader.xrefs.total_revisions):
        for reference in reader.xrefs.explicit_refs_in_revision(revision):
            try:
                pending.append(reader.get_object(reference))  # type: ignore[no-untyped-call]
            except Exception:
                continue
    seen: set[int] = set()
    while pending and len(found) < MAX_DICTIONARIES:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, generic.DictionaryObject):
            found.append(item)
            pending.extend(item.values())
        elif isinstance(item, generic.ArrayObject):
            pending.extend(item)
    return found


def _has_filter(dictionary: generic.DictionaryObject, name: str) -> bool:
    value = dictionary.get("/Filter")
    if isinstance(value, generic.ArrayObject):
        return any(str(item) == name for item in value)
    return str(value) == name


def _font_is_embedded(font: generic.DictionaryObject) -> bool:
    if "/DescendantFonts" in font:
        return True  # the descendant carries the descriptor; checked on its own dictionary
    descriptor = font.get("/FontDescriptor")
    if descriptor is None:
        return False
    descriptor = descriptor.get_object()
    return any(key in descriptor for key in ("/FontFile", "/FontFile2", "/FontFile3"))


def _content_violations(reader: PdfFileReader, declared_part: str | None) -> list[str]:
    violations: set[str] = set()
    first_part = (declared_part or "")[:1]
    for dictionary in _dictionaries(reader):
        if str(dictionary.get("/Type")) == "/Font" and not _font_is_embedded(dictionary):
            violations.add("font_not_embedded")
        if str(dictionary.get("/S")) == "/JavaScript" or "/JavaScript" in dictionary:
            violations.add("javascript_present")
        if str(dictionary.get("/S")) == "/Launch":
            violations.add("launch_action_present")
        if _has_filter(dictionary, "/LZWDecode"):
            violations.add("lzw_compression")
        # attachments and transparency are forbidden by PDF/A-1 alone
        if first_part == "1":
            if "/EmbeddedFiles" in dictionary:
                violations.add("embedded_files_present")
            group = dictionary.get("/Group")
            if group is not None:
                resolved = group.get_object()
                if str(resolved.get("/S")) == "/Transparency":
                    violations.add("transparency_present")
            if "/SMask" in dictionary:
                violations.add("transparency_present")
    return sorted(violations)


def check_pdfa(pdf: bytes) -> PdfaReport:
    if not pdf.startswith(b"%PDF-"):
        # an established non-PDF is never described to the user in PDF/A terms
        return PdfaReport(PdfaStatus.NOT_APPLICABLE)
    try:
        reader = PdfFileReader(io.BytesIO(pdf), strict=False)
        if reader.security_handler is not None:
            # we do not unlock documents, so the checks simply cannot be run
            return PdfaReport(PdfaStatus.INDETERMINATE, ["encrypted_pdf"])
        root = reader.root
        violations = []
        declared_part = None
        if "/Metadata" in root:
            declared_part = _declared_part(root["/Metadata"].data)
        if declared_part is None:
            violations.append("missing_pdfa_identification")
        if "/OutputIntents" not in root:
            violations.append("missing_output_intent")
        violations.extend(_content_violations(reader, declared_part))
    except (PdfError, PdfReadError, KeyError, TypeError, ValueError, OSError):
        return PdfaReport(PdfaStatus.INDETERMINATE, ["unreadable_pdf"])
    if violations:
        return PdfaReport(PdfaStatus.NON_CONFORMANT, violations, declared_part)
    return PdfaReport(PdfaStatus.CONFORMANT, [], declared_part)
