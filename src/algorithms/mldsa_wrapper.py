"""
ML-DSA Wrapper (FIPS 204, ehemals CRYSTALS-Dilithium).

Verwendet liboqs-python. ML-DSA ist gitterbasiert und stateless,
d.h. der Secret Key kann beliebig oft zum Signieren verwendet werden.

Verfuegbare Parametersets in liboqs:
    - ML-DSA-44   (NIST Level 2, Empfehlung fuer "AES-128-aequivalent")
    - ML-DSA-65   (NIST Level 3)
    - ML-DSA-87   (NIST Level 5, hoechste Sicherheit)
"""
from __future__ import annotations
import oqs

from .base import SignatureScheme, KeyPair


# Mapping unserer freundlichen Namen auf liboqs-Bezeichnungen
PARAMETER_SETS = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
}


class MLDSAScheme(SignatureScheme):
    def __init__(self, parameter_set: str = "ML-DSA-65"):
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(
                f"Unbekanntes Parameterset: {parameter_set}. "
                f"Verfuegbar: {list(PARAMETER_SETS.keys())}"
            )
        self._parameter_set = parameter_set
        self._oqs_name = PARAMETER_SETS[parameter_set]

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
            algorithm="ML-DSA",
            parameter_set=self._parameter_set,
        )

    def sign(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        with oqs.Signature(self._oqs_name, secret_key=secret_key) as signer:
            signature = signer.sign(message)
        # ML-DSA ist stateless => secret_key bleibt identisch
        return signature, secret_key

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
