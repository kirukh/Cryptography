"""
XMSS Wrapper (RFC 8391) - das Herzstueck des Projekts.

WICHTIG: XMSS ist STATEFUL. Der Secret Key enthaelt einen Index, der
nach jeder Signatur inkrementiert werden MUSS. Wird derselbe Index
zweimal verwendet, kann ein Angreifer aus den beiden Signaturen
Forgeries unter dem Public Key erzeugen.

Implementierungs-Strategie:
- Wir nutzen liboqs-python, FALLS XMSS in liboqs aktiviert ist.
- Sonst verwenden wir die offizielle xmss-reference (Subprocess).

Das Schoene: liboqs-python liefert nach jedem sign() den AKTUALISIERTEN
Secret Key zurueck. Damit haben wir vollstaendige Kontrolle ueber den
State - wir koennen ihn absichtlich falsch persistieren, kopieren,
auf mehreren Knoten gleichzeitig nutzen etc. Genau das brauchen wir
fuer die Statefulness-Demos in Schritt 4.

Verfuegbare Parametersets (RFC 8391):
    XMSS-SHA2_10_256  : 2^10 = 1024 Signaturen, SHA-256
    XMSS-SHA2_16_256  : 2^16 = 65k Signaturen
    XMSS-SHA2_20_256  : 2^20 = ~1M Signaturen (aber sehr lange Keygen!)
"""
from __future__ import annotations
import oqs

from .base import SignatureScheme, KeyPair


PARAMETER_SETS = {
    "XMSS-SHA2_10_256": "XMSS-SHA2_10_256",
    "XMSS-SHA2_16_256": "XMSS-SHA2_16_256",
    "XMSS-SHA2_20_256": "XMSS-SHA2_20_256",
}


class XMSSNotEnabledError(RuntimeError):
    """Wird geworfen, wenn liboqs ohne XMSS-Support gebaut wurde.

    Das ist der DEFAULT bei liboqs - aus genau dem Grund, den wir
    in der Arbeit diskutieren: die Statefulness-Gefahr.
    """


class XMSSScheme(SignatureScheme):
    def __init__(self, parameter_set: str = "XMSS-SHA2_10_256"):
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(
                f"Unbekanntes Parameterset: {parameter_set}. "
                f"Verfuegbar: {list(PARAMETER_SETS.keys())}"
            )
        self._parameter_set = parameter_set
        self._oqs_name = PARAMETER_SETS[parameter_set]

        # Pruefung: ist XMSS in diesem liboqs-Build ueberhaupt enabled?
        # XMSS sitzt in liboqs unter den "stateful sig mechanisms",
        # nicht unter den normalen sig mechanisms.
        try:
            enabled_stateful = oqs.get_enabled_stateful_sig_mechanisms()
        except AttributeError:
            raise XMSSNotEnabledError(
                "Dein liboqs-python kennt keine stateful-Signaturen. "
                "Du brauchst liboqs >= 0.10 mit OQS_ENABLE_SIG_STFL_XMSS=ON, "
                "und liboqs-python aus dem 'stfl-key-sigs'-Branch oder "
                "main >= 0.10."
            )

        if self._oqs_name not in enabled_stateful:
            raise XMSSNotEnabledError(
                f"{self._oqs_name} ist nicht aktiviert. "
                f"liboqs muss mit folgenden CMake-Flags gebaut werden:\n"
                f"  -DOQS_ENABLE_SIG_STFL_XMSS=ON\n"
                f"  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON\n"
                f"Aktivierte stateful-Mechanismen: {enabled_stateful}"
            )

    @property
    def name(self) -> str:
        return self._parameter_set

    @property
    def is_stateful(self) -> bool:
        return True

    def keygen(self) -> KeyPair:
        # liboqs hat fuer stateful-sigs eine eigene Klasse: StatefulSignature
        with oqs.StatefulSignature(self._oqs_name) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return KeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm="XMSS",
            parameter_set=self._parameter_set,
        )

    def sign(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        """Signiert und gibt den AKTUALISIERTEN Secret Key zurueck.

        Der zurueckgegebene secret_key ist NICHT identisch mit dem Input -
        der interne Index wurde inkrementiert. Wer den alten secret_key
        weiterverwendet, signiert mit demselben Index erneut und liefert
        einem Angreifer damit alle Bausteine fuer eine Forgery.
        """
        with oqs.StatefulSignature(self._oqs_name, secret_key=secret_key) as signer:
            signature = signer.sign(message)
            updated_secret_key = signer.export_secret_key()
        return signature, updated_secret_key

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.StatefulSignature(self._oqs_name) as verifier:
            return verifier.verify(message, signature, public_key)

    def signature_size(self) -> int:
        with oqs.StatefulSignature(self._oqs_name) as s:
            return s.details["length_signature"]

    def public_key_size(self) -> int:
        with oqs.StatefulSignature(self._oqs_name) as s:
            return s.details["length_public_key"]

    def secret_key_size(self) -> int:
        with oqs.StatefulSignature(self._oqs_name) as s:
            return s.details["length_secret_key"]

    def remaining_signatures(self, secret_key: bytes) -> int:
        """Wie viele Signaturen sind mit diesem Key noch moeglich?

        Das ist ein XMSS-spezifischer Helfer, den die anderen Algorithmen
        nicht haben - in der Statefulness-Demo wichtig.
        """
        with oqs.StatefulSignature(self._oqs_name, secret_key=secret_key) as s:
            return s.sigs_remaining()
