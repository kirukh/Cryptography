"""
SPHINCS+ / SLH-DSA Wrapper (FIPS 205).

Stateless Hash-Based Signatures - der "sichere Bruder" von XMSS.
Im Gegensatz zu XMSS muss kein State verwaltet werden, dafuer sind
Signaturen deutlich groesser und Signing langsamer.

Naming-Konvention:
    -s = "small signatures, slow signing"
    -f = "fast signing, larger signatures"

Wichtig: NIST hat das Naming auf SLH-DSA umgestellt. liboqs unterstuetzt
beide Varianten - wir nutzen die SHA2-Familie als Default.
"""
from __future__ import annotations
import oqs

from .base import SignatureScheme, KeyPair


# Auswahl gaengiger Parametersets, Mapping zu liboqs-Namen.
# Die genauen Strings koennen je nach liboqs-Version variieren -
# wir validieren beim Init gegen oqs.get_enabled_sig_mechanisms().
PARAMETER_SETS = {
    # Format: "Friendly-Name": "liboqs-internal-name"
    "SPHINCS+-128s": "SPHINCS+-SHA2-128s-simple",
    "SPHINCS+-128f": "SPHINCS+-SHA2-128f-simple",
    "SPHINCS+-192s": "SPHINCS+-SHA2-192s-simple",
    "SPHINCS+-192f": "SPHINCS+-SHA2-192f-simple",
    "SPHINCS+-256s": "SPHINCS+-SHA2-256s-simple",
    "SPHINCS+-256f": "SPHINCS+-SHA2-256f-simple",
}


class SPHINCSScheme(SignatureScheme):
    def __init__(self, parameter_set: str = "SPHINCS+-128f"):
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(
                f"Unbekanntes Parameterset: {parameter_set}. "
                f"Verfuegbar: {list(PARAMETER_SETS.keys())}"
            )
        self._parameter_set = parameter_set
        self._oqs_name = PARAMETER_SETS[parameter_set]

        # Sanity-Check: ist dieses Parameterset im aktuellen liboqs-Build aktiv?
        enabled = oqs.get_enabled_sig_mechanisms()
        if self._oqs_name not in enabled:
            raise RuntimeError(
                f"{self._oqs_name} ist nicht in deinem liboqs-Build aktiviert.\n"
                f"Aktivierte SPHINCS+-Varianten:\n  "
                + "\n  ".join(m for m in enabled if "SPHINCS" in m)
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
            algorithm="SPHINCS+",
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
