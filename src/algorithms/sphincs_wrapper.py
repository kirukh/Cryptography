"""
SLH-DSA Wrapper (FIPS 205, frueher CRYSTALS-SPHINCS+).

Stateless Hash-Based Signatures - der "sichere Bruder" von XMSS.
Im Gegensatz zu XMSS muss kein State verwaltet werden, dafuer sind
Signaturen deutlich groesser und Signing langsamer.

Naming:
    -s = "small signatures, slow signing"  (langsam, kleinere Signatur)
    -f = "fast signing, larger signatures" (schnell, groessere Signatur)

In liboqs 0.15 sind die Mechanismen entsprechend FIPS 205 benannt:
    SLH_DSA_PURE_<HASH>_<LEVEL><S|F>
    - PURE  : keine Pre-Hashing-Variante (Standardfall)
    - HASH  : SHA2 oder SHAKE
    - LEVEL : 128, 192 oder 256 (Bit Sicherheitsstaerke)

Wir nutzen die SHA2-PURE-Familie als Default - das ist das, was die
meisten Vergleichstabellen in der Literatur verwenden.
"""
from __future__ import annotations
import oqs

from .base import SignatureScheme, KeyPair


# Friendly-Name -> liboqs-Name (FIPS 205)
# Wir behalten "SPHINCS+"-Bezeichnung als Friendly-Name fuer Konsistenz mit
# aelterer Literatur, mappen aber auf den FIPS-Namen.
PARAMETER_SETS = {
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
    "SLH-DSA-SHA2-128f": "SLH_DSA_PURE_SHA2_128F",
    "SLH-DSA-SHA2-192s": "SLH_DSA_PURE_SHA2_192S",
    "SLH-DSA-SHA2-192f": "SLH_DSA_PURE_SHA2_192F",
    "SLH-DSA-SHA2-256s": "SLH_DSA_PURE_SHA2_256S",
    "SLH-DSA-SHA2-256f": "SLH_DSA_PURE_SHA2_256F",
    # SHAKE-Varianten - relevant, falls man SHA-3-basiert vergleichen will
    "SLH-DSA-SHAKE-128s": "SLH_DSA_PURE_SHAKE_128S",
    "SLH-DSA-SHAKE-128f": "SLH_DSA_PURE_SHAKE_128F",
    "SLH-DSA-SHAKE-256s": "SLH_DSA_PURE_SHAKE_256S",
    "SLH-DSA-SHAKE-256f": "SLH_DSA_PURE_SHAKE_256F",
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


# Rueckwaertskompatibler Alias - falls du irgendwo schon "SPHINCSScheme"
# im Code stehen hast, funktioniert das damit weiter.
SPHINCSScheme = SLHDSAScheme
