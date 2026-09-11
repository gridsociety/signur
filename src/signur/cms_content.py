from dataclasses import dataclass

from asn1crypto import cms  # type: ignore[import-untyped]


class CmsContentError(ValueError):
    pass


@dataclass(frozen=True)
class EmbeddedCmsContent:
    content: bytes
    nesting_depth: int


def extract_attached_content(container: bytes) -> bytes:
    try:
        content_info = cms.ContentInfo.load(container, strict=True)
        if content_info["content_type"].native != "signed_data":
            raise CmsContentError("Il contenitore CMS non è SignedData.")
        signed_data = content_info["content"]
        if not signed_data["signer_infos"]:
            raise CmsContentError("Il contenitore CMS non contiene firme.")
        content = signed_data["encap_content_info"]["content"].native
        if not isinstance(content, bytes):
            raise CmsContentError("Il contenitore CMS non include il contenuto firmato.")
        return content
    except CmsContentError:
        raise
    except Exception as exc:
        raise CmsContentError("Il contenitore CMS non è decodificabile.") from exc


def extract_nested_content(container: bytes, max_depth: int = 8) -> EmbeddedCmsContent:
    current = extract_attached_content(container)
    depth = 1
    while depth < max_depth:
        try:
            nested = extract_attached_content(current)
        except CmsContentError:
            break
        current = nested
        depth += 1
    else:
        try:
            extract_attached_content(current)
        except CmsContentError:
            pass
        else:
            raise CmsContentError("Il contenitore CMS supera il limite di annidamento.")
    return EmbeddedCmsContent(content=current, nesting_depth=depth)


def is_attached_cms(container: bytes) -> bool:
    try:
        extract_attached_content(container)
    except CmsContentError:
        return False
    return True
