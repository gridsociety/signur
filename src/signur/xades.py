import hashlib
from base64 import b64decode, b64encode
from typing import Any, cast

from cryptography.hazmat.primitives import serialization
from lxml import etree  # type: ignore[import-untyped]
from signxml import (  # type: ignore[attr-defined]
    CanonicalizationMethod,
    SignatureConstructionMethod,
)
from signxml.xades import XAdESSigner, XAdESVerifier  # type: ignore[attr-defined]

from signur.models import XadesPackaging
from signur.signing_proxy import SigningClient, SigningIdentity

CONTENT_NAMESPACE = "urn:signur:enveloping:1"
DSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"


class XadesError(Exception):
    pass


class _Signer(XAdESSigner):
    """signxml stamps its own name on the generated identifiers; ours stay neutral.

    It only fills them in when they are missing, so setting them first is enough.
    A test asserts the library name never reaches the output, and will fail loudly
    if a future version stops honouring this.
    """

    def _build_xades_ds_object(self, sig_root: Any, signing_settings: Any) -> Any:
        if "Id" not in sig_root.attrib:
            sig_root.set("Id", f"Signature-{self._get_token()}")  # type: ignore[no-untyped-call]
        key_info = self._find(sig_root, "KeyInfo")  # type: ignore[no-untyped-call]
        if "Id" not in key_info.attrib:
            key_info.set("Id", f"KeyInfo-{self._get_token()}")  # type: ignore[no-untyped-call]
        return super()._build_xades_ds_object(sig_root, signing_settings)

    def add_data_object_format(
        self, signed_data_object_properties: Any, sig_root: Any, signing_settings: Any
    ) -> Any:
        signed_info = self._find(sig_root, "ds:SignedInfo")  # type: ignore[no-untyped-call]
        reference = self._find(signed_info, "ds:Reference")  # type: ignore[no-untyped-call]
        if "Id" not in reference.attrib:
            reference.set("Id", f"Reference-{self._get_token()}")  # type: ignore[no-untyped-call]
        return super().add_data_object_format(
            signed_data_object_properties, sig_root, signing_settings
        )


class CardPrivateKey:
    """Looks like an RSA private key to signxml; the card only ever sees a digest."""

    def __init__(self, client: SigningClient, identity: SigningIdentity) -> None:
        self._client = client
        self._identity = identity
        self.key_size = identity.signature_length * 8

    def public_key(self) -> Any:
        return self._identity.certificate.public_key()

    def sign(self, data: bytes, padding: Any = None, algorithm: Any = None) -> bytes:
        return self._client.sign_digest(hashlib.sha256(data).digest(), self._identity)


def _parse(original: bytes) -> etree._Element:
    """Parse defensively: no DTD, no entities, no network, no unbounded trees."""
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        dtd_validation=False,
        no_network=True,
        huge_tree=False,
    )
    try:
        document = etree.fromstring(original, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise XadesError("L'XML non è analizzabile.") from exc
    if document.getroottree().docinfo.internalDTD is not None:
        raise XadesError("Un XML con dichiarazione DOCTYPE non è firmabile in XAdES.")
    return document


def _content_element(original: bytes) -> etree._Element:
    """Wrap the original bytes in Base64 so signing cannot rewrite them."""
    element = etree.Element(f"{{{CONTENT_NAMESPACE}}}Contenuto", nsmap={None: CONTENT_NAMESPACE})
    element.set("Codifica", "base64")
    element.text = b64encode(original).decode()
    return element


def build_xades_b_b(
    original: bytes,
    client: SigningClient,
    identity: SigningIdentity,
    packaging: XadesPackaging,
) -> bytes:
    if packaging is XadesPackaging.ENVELOPING:
        _parse(original)  # refuse hostile or broken XML before wrapping it
        payload = _content_element(original)
        method = SignatureConstructionMethod.enveloping
    else:
        payload = _parse(original)
        method = SignatureConstructionMethod.enveloped
    signer = _Signer(
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        method=method,
        # comments belong to the document, so the signature must cover them
        c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_1_WITH_COMMENTS,
    )
    certificate_pem = identity.certificate.public_bytes(serialization.Encoding.PEM).decode()
    # signxml only ever calls sign() and public_key() on the key, so the card stands in
    key = cast(Any, CardPrivateKey(client, identity))
    signed = signer.sign(payload, key=key, cert=[certificate_pem])
    # The signature covers the root element, so that is exactly what we serialise:
    # anything before the root, such as a leading comment, is outside its reach.
    return bytes(etree.tostring(signed, xml_declaration=True, encoding="UTF-8"))


def verify_xades_b_b(
    result: bytes,
    original: bytes,
    packaging: XadesPackaging,
    identity: SigningIdentity,
) -> None:
    """Prove the signature holds and, for enveloping, that the bytes came back whole."""
    try:
        tree = etree.fromstring(result)
        references = tree.findall(
            f".//{{{DSIG_NAMESPACE}}}SignedInfo/{{{DSIG_NAMESPACE}}}Reference"
        )
        XAdESVerifier().verify(
            tree, x509_cert=identity.certificate, expect_references=len(references)
        )
        if packaging is XadesPackaging.ENVELOPING:
            content = tree.find(f".//{{{CONTENT_NAMESPACE}}}Contenuto")
            if content is None or b64decode(content.text or "") != original:
                raise XadesError("Il contenitore non conserva i byte originali.")
    except XadesError:
        raise
    except Exception as exc:
        raise XadesError("La firma XAdES generata non è valida.") from exc
