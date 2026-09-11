from base64 import b64decode
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fake_card import DirectSigningClient
from lxml import etree

from signur.models import XadesPackaging
from signur.xades import XadesError, build_xades_b_b, verify_xades_b_b

DS = "http://www.w3.org/2000/09/xmldsig#"
CONTENT = "urn:signur:enveloping:1"
ORIGINAL = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<fattura   xmlns="urn:prova"  versione="1.2">\n'
    "  <!-- riga di prova -->\n"
    '  <riga importo="10,00">caffè &amp; cornetto</riga>\n'
    "</fattura>\n"
).encode()


def _references(signed: bytes) -> list[str]:
    tree = etree.fromstring(signed)
    return [item.get("URI") for item in tree.findall(f".//{{{DS}}}SignedInfo/{{{DS}}}Reference")]


def test_enveloped_signature_lives_inside_the_document() -> None:
    card = DirectSigningClient("Signur XAdES test")

    signed = build_xades_b_b(ORIGINAL, card, card.identity, XadesPackaging.ENVELOPED)

    tree = etree.fromstring(signed)
    assert etree.QName(tree).localname == "fattura"
    assert tree.find(f"{{{DS}}}Signature") is not None
    assert "" in _references(signed)
    assert b"QualifyingProperties" in signed


def test_enveloping_keeps_the_original_bytes_exactly() -> None:
    card = DirectSigningClient("Signur XAdES test")

    signed = build_xades_b_b(ORIGINAL, card, card.identity, XadesPackaging.ENVELOPING)

    tree = etree.fromstring(signed)
    assert etree.QName(tree).localname == "Signature"
    assert "#object" in _references(signed)
    content = tree.find(f".//{{{CONTENT}}}Contenuto")
    assert content is not None
    assert b64decode(content.text) == ORIGINAL


def test_the_card_signs_one_digest_per_signature() -> None:
    card = DirectSigningClient("Signur XAdES test")
    seen: list[bytes] = []
    original_sign = card.sign_digest
    card.sign_digest = lambda digest, identity: (
        seen.append(digest),
        original_sign(digest, identity),
    )[1]  # type: ignore[method-assign]

    build_xades_b_b(ORIGINAL, card, card.identity, XadesPackaging.ENVELOPED)

    assert len(seen) == 1
    assert len(seen[0]) == 32


def test_verification_accepts_what_it_produced() -> None:
    card = DirectSigningClient("Signur XAdES test")

    for packaging in (XadesPackaging.ENVELOPED, XadesPackaging.ENVELOPING):
        signed = build_xades_b_b(ORIGINAL, card, card.identity, packaging)
        verify_xades_b_b(signed, ORIGINAL, packaging, card.identity)


def test_verification_rejects_a_tampered_amount() -> None:
    card = DirectSigningClient("Signur XAdES test")
    signed = build_xades_b_b(ORIGINAL, card, card.identity, XadesPackaging.ENVELOPED)

    tampered = signed.replace(b"10,00", b"99,00")

    assert tampered != signed
    with pytest.raises(XadesError):
        verify_xades_b_b(tampered, ORIGINAL, XadesPackaging.ENVELOPED, card.identity)


def test_an_xml_with_an_external_entity_is_refused(tmp_path: Path) -> None:
    secret = tmp_path / "segreto.txt"
    secret.write_text("PIN-SEGRETO-1234")
    hostile = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE fattura [<!ENTITY furto SYSTEM "file://{secret}">]>'
        "<fattura>&furto;</fattura>"
    ).encode()
    card = DirectSigningClient("Signur XAdES test")

    with pytest.raises(XadesError):
        build_xades_b_b(hostile, card, card.identity, XadesPackaging.ENVELOPED)


def test_an_xml_that_does_not_parse_is_refused() -> None:
    card = DirectSigningClient("Signur XAdES test")

    with pytest.raises(XadesError):
        build_xades_b_b(b"<fattura><riga></fattura>", card, card.identity, XadesPackaging.ENVELOPED)


def test_an_xml_with_a_doctype_is_refused_even_when_harmless() -> None:
    card = DirectSigningClient("Signur XAdES test")
    with_doctype = b'<?xml version="1.0"?><!DOCTYPE fattura><fattura><riga>uno</riga></fattura>'

    with pytest.raises(XadesError):
        build_xades_b_b(with_doctype, card, card.identity, XadesPackaging.ENVELOPED)


def test_the_signature_verifies_without_signxml() -> None:
    card = DirectSigningClient("Signur XAdES test")
    signed = build_xades_b_b(ORIGINAL, card, card.identity, XadesPackaging.ENVELOPED)

    tree = etree.fromstring(signed)
    signed_info = tree.find(f".//{{{DS}}}SignedInfo")
    canonical = etree.tostring(signed_info, method="c14n", exclusive=False, with_comments=False)
    value = b64decode(tree.find(f".//{{{DS}}}SignatureValue").text)

    card.identity.certificate.public_key().verify(
        value, canonical, padding.PKCS1v15(), hashes.SHA256()
    )


def test_altering_a_comment_breaks_the_signature() -> None:
    card = DirectSigningClient("Signur XAdES test")
    signed = build_xades_b_b(ORIGINAL, card, card.identity, XadesPackaging.ENVELOPED)

    tampered = signed.replace(b"riga di prova", b"riga contraffatta")

    assert tampered != signed
    with pytest.raises(XadesError):
        verify_xades_b_b(tampered, ORIGINAL, XadesPackaging.ENVELOPED, card.identity)


def test_the_signature_does_not_name_the_library_that_made_it() -> None:
    card = DirectSigningClient("Signur XAdES test")

    for packaging in (XadesPackaging.ENVELOPED, XadesPackaging.ENVELOPING):
        signed = build_xades_b_b(ORIGINAL, card, card.identity, packaging)
        assert b"SignXML" not in signed, signed[:400]
