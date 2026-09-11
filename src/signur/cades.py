import asyncio
from typing import cast

from asn1crypto import cms  # type: ignore[import-untyped]
from pyhanko.sign import validation

from signur.proxy_signer import SIGNATURE_ALGORITHM_POLICY, ProxySigner
from signur.signing_proxy import SigningClient, SigningIdentity


class CadesError(Exception):
    pass


async def build_cades_b_b_async(
    content: bytes, client: SigningClient, identity: SigningIdentity
) -> bytes:
    signer = ProxySigner(client, identity)
    container = await signer.async_sign_general_data(
        content,
        digest_algorithm="sha256",
        detached=False,
        use_cades=True,
    )
    encoded = cast(bytes, container.dump())
    await verify_cades_b_b_async(encoded, content)
    return encoded


def build_cades_b_b(content: bytes, client: SigningClient, identity: SigningIdentity) -> bytes:
    return asyncio.run(build_cades_b_b_async(content, client, identity))


async def build_cades_parallel_b_b_async(
    container: bytes, client: SigningClient, identity: SigningIdentity
) -> bytes:
    try:
        content_info = cms.ContentInfo.load(container, strict=True)
        if content_info["content_type"].native != "signed_data":
            raise CadesError("Il P7M non è un contenitore CMS SignedData.")
        signed_data = content_info["content"]
        embedded_content = signed_data["encap_content_info"]["content"].native
        if not isinstance(embedded_content, bytes):
            raise CadesError("Il P7M non contiene dati incorporati.")
        previous_signers = {item.dump() for item in signed_data["signer_infos"]}

        signer = ProxySigner(client, identity)
        added_container = await signer.async_sign_general_data(
            signed_data["encap_content_info"],
            digest_algorithm="sha256",
            detached=False,
            use_cades=True,
        )
        added_encoded = cast(bytes, added_container.dump())
        await verify_cades_b_b_async(added_encoded, embedded_content)
        added_data = cms.ContentInfo.load(added_encoded, strict=True)["content"]
        added_signer = added_data["signer_infos"][0]

        known_digests = {item.dump() for item in signed_data["digest_algorithms"]}
        for algorithm in added_data["digest_algorithms"]:
            if algorithm.dump() not in known_digests:
                signed_data["digest_algorithms"].append(algorithm)

        known_certificates = {item.dump() for item in signed_data["certificates"]}
        for certificate in added_data["certificates"]:
            if certificate.dump() not in known_certificates:
                signed_data["certificates"].append(certificate)
        signed_data["signer_infos"].append(added_signer)
        encoded = cast(bytes, content_info.dump())

        reparsed = cms.ContentInfo.load(encoded, strict=True)["content"]
        if reparsed["encap_content_info"]["content"].native != embedded_content:
            raise CadesError("La firma parallela ha modificato il contenuto incorporato.")
        result_signers = {item.dump() for item in reparsed["signer_infos"]}
        if (
            not previous_signers.issubset(result_signers)
            or added_signer.dump() not in result_signers
        ):
            raise CadesError("La firma parallela non ha preservato tutti i firmatari.")
        return encoded
    except CadesError:
        raise
    except Exception as exc:
        raise CadesError("Il P7M non consente una firma CAdES parallela.") from exc


def build_cades_parallel_b_b(
    container: bytes, client: SigningClient, identity: SigningIdentity
) -> bytes:
    return asyncio.run(build_cades_parallel_b_b_async(container, client, identity))


async def verify_cades_b_b_async(container: bytes, expected_content: bytes) -> None:
    try:
        content_info = cms.ContentInfo.load(container, strict=True)
        if content_info["content_type"].native != "signed_data":
            raise CadesError("Il risultato non è un contenitore CMS SignedData.")
        signed_data = content_info["content"]
        embedded = signed_data["encap_content_info"]["content"].native
        if embedded != expected_content:
            raise CadesError("Il contenuto incorporato non coincide con l'originale.")
        signer_infos = signed_data["signer_infos"]
        if len(signer_infos) != 1:
            raise CadesError("Il contenitore deve avere esattamente un firmatario Signur.")
        signed_attribute_types = {
            attribute["type"].native for attribute in signer_infos[0]["signed_attrs"]
        }
        required = {"content_type", "message_digest", "signing_certificate_v2"}
        if not required.issubset(signed_attribute_types):
            raise CadesError("Mancano attributi firmati obbligatori CAdES-B-B.")
        status = await validation.async_validate_cms_signature(
            signed_data,
            algorithm_policy=SIGNATURE_ALGORITHM_POLICY,  # type: ignore[call-overload]
        )
        if not status.intact or not status.valid:
            raise CadesError("La verifica crittografica del CAdES è fallita.")
    except CadesError:
        raise
    except Exception as exc:
        raise CadesError("Il contenitore CAdES generato non è valido.") from exc


def verify_cades_b_b(container: bytes, expected_content: bytes) -> None:
    asyncio.run(verify_cades_b_b_async(container, expected_content))
