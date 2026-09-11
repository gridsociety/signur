import asyncio
import hashlib

from asn1crypto import algos, x509  # type: ignore[import-untyped]
from pyhanko.sign import signers
from pyhanko.sign.validation.utils import CMSAlgorithmUsagePolicy
from pyhanko_certvalidator.policy_decl import DisallowWeakAlgorithmsPolicy

from signur.signing_proxy import SigningClient, SigningIdentity

# Cards in circulation still carry 1024 bit RSA keys, and a file signed with one
# can still be accepted in some settings. So the shorter key earns a warning
# rather than a refusal, while broken digests such as SHA-1 stay forbidden.
SIGNATURE_ALGORITHM_POLICY = CMSAlgorithmUsagePolicy.lift_policy(
    DisallowWeakAlgorithmsPolicy(rsa_key_size_threshold=1024)  # type: ignore[no-untyped-call]
)
WEAK_KEY_BITS = 2048


class ProxySignerError(Exception):
    pass


class ProxySigner(signers.Signer):
    def __init__(self, client: SigningClient, identity: SigningIdentity) -> None:
        super().__init__(
            signing_cert=x509.Certificate.load(identity.certificate_der),
            cert_registry=None,
            signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            prefer_pss=False,
            embed_roots=False,
        )
        self._client = client
        self._identity = identity

    async def async_sign_raw(
        self, data: bytes, digest_algorithm: str, dry_run: bool = False
    ) -> bytes:
        if digest_algorithm.lower() != "sha256":
            raise ProxySignerError("Signur supporta soltanto SHA-256.")
        if dry_run:
            return bytes(self._identity.signature_length)
        digest = hashlib.sha256(data).digest()
        return await asyncio.to_thread(self._client.sign_digest, digest, self._identity)
