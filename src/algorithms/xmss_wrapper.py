"""
XMSS Wrapper (RFC 8391) - das Herzstueck des Projekts.

WICHTIG: XMSS ist STATEFUL. Der Secret Key enthaelt einen Index, der
nach jeder Signatur inkrementiert werden MUSS. Wird derselbe Index
zweimal verwendet, kann ein Angreifer aus den beiden Signaturen
Forgeries unter dem Public Key erzeugen.

liboqs-python liefert nach jedem sign() den AKTUALISIERTEN Secret Key
zurueck. Damit haben wir Kontrolle ueber den State - wir koennen ihn
auch absichtlich falsch persistieren, kopieren, usw. Genau das brauchen
wir fuer die Statefulness-Demos.

Verfuegbares Parameterset:
    XMSS-SHA2_10_256  : 2^10 = 1024 Signaturen, SHA-256
"""
from __future__ import annotations
import oqs

from .base import SignatureScheme, KeyPair


PARAMETER_SETS = {
    "XMSS-SHA2_10_256": "XMSS-SHA2_10_256",
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
        # XMSS sitzt in liboqs unter den "stateful sig mechanisms".
        try:
            enabled_stateful = oqs.get_enabled_stateful_sig_mechanisms()
        except AttributeError:
            raise XMSSNotEnabledError(
                "Dein liboqs-python kennt keine stateful-Signaturen. "
                "Stelle sicher, dass liboqs >= 0.10 mit aktiviertem "
                "Stateful-Support gebaut wurde und liboqs-python aus dem "
                "Quellcode installiert ist (siehe setup_liboqs.sh)."
            )

        if self._oqs_name not in enabled_stateful:
            raise XMSSNotEnabledError(
                f"{self._oqs_name} ist nicht aktiviert.\n"
                f"liboqs muss mit aktiviertem Stateful-Support gebaut "
                f"werden (siehe setup_liboqs.sh). Der genaue Name des "
                f"HAZARDOUS-Flags kann je nach liboqs-Version variieren; "
                f"in liboqs/CMakeLists.txt die verfuegbaren "
                f"OQS_ENABLE_SIG_STFL_*- und OQS_HAZARDOUS_*-Optionen "
                f"pruefen.\n"
                f"Aktivierte stateful-Mechanismen: {enabled_stateful}"
            )

    @property
    def name(self) -> str:
        return self._parameter_set

    @property
    def is_stateful(self) -> bool:
        return True

    def keygen(self) -> KeyPair:
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
        weiterverwendet, signiert mit demselben Index erneut.
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
        """Anzahl der mit diesem Key noch moeglichen Signaturen.

        Hinweis zur liboqs-Konvention: direkt nach keygen() liefert
        liboqs fuer XMSS-SHA2_10_256 den Wert 1023, nicht 1024. Der
        initiale Index 0 wird intern als 'allokiert, aber noch nicht
        verbraucht' gezaehlt. Funktional ohne Konsequenz: der Counter
        sinkt pro sign() exakt um 1, und die Reuse-Eigenschaft bleibt
        unveraendert.
        """
        with oqs.StatefulSignature(self._oqs_name, secret_key=secret_key) as s:
            return s.sigs_remaining()
