"""
SLH-DSA Wrapper (FIPS 205, frueher SPHINCS+).

Stateless Hash-Based Signatures - der "sichere Bruder" von XMSS.
Im Gegensatz zu XMSS muss kein State verwaltet werden, dafuer sind
Signaturen deutlich groesser und Signing langsamer.

Wir benchmarken die SHA2-128f-Variante (fast signing, NIST Level 1) -
das ist ein gaengiger Vergleichspunkt in der Literatur.
"""
from __future__ import annotations
import oqs

from .base import SignatureScheme, KeyPair


# Friendly-Name -> liboqs-Name (FIPS 205)
PARAMETER_SETS = {
    "SLH-DSA-SHA2-128f": "SLH_DSA_PURE_SHA2_128F",
}


class SLHDSAScheme(SignatureScheme):
    def __init__(self, parameter_set: str = "SLH-DSA-SHA2-128f"):
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(
                f"Unbekanntes Parameterset: {parameter_set}. "
                f"Verfuegbar: {list(PARAMETER_SETS.keys())}"
            )
        self._parameter_set = parameter_set
        self._oqs_name = PARAMETER_SETS[parameter_set]

        # Sanity-Check
        enabled = oqs.get_enabled_sig_mechanisms()
        if self._oqs_name not in enabled:
            raise RuntimeError(
                f"{self._oqs_name} ist nicht in deinem liboqs-Build aktiviert."
            )

    @property
    def name(self) -> str:
        return self._parameter_set

    @property
    def is_stateful(self) -> bool:
        return False

    def keygen(self) -> KeyPair:
        with oqs.Signature(self._oqs_name) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return KeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm="SLH-DSA",
            parameter_set=self._parameter_set,
        )

    def sign(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        with oqs.Signature(self._oqs_name, secret_key=secret_key) as signer:
            signature = signer.sign(message)
        return signature, secret_key  # stateless

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self._oqs_name) as verifier:
            return verifier.verify(message, signature, public_key)

    def signature_size(self) -> int:
        with oqs.Signature(self._oqs_name) as s:
            return s.details["length_signature"]

    def public_key_size(self) -> int:
        with oqs.Signature(self._oqs_name) as s:
            return s.details["length_public_key"]

    def secret_key_size(self) -> int:
        with oqs.Signature(self._oqs_name) as s:
            return s.details["length_secret_key"]
