"""
Tests fuer das STATEFUL-Verhalten von XMSS.

Dies ist der inhaltlich wichtigste Test-Block der gesamten Arbeit.
Wenn diese Tests nicht laufen oder unsauber sind, hat die ganze
Statefulness-Argumentation kein solides Fundament.

Was wir testen:
- Index-Progression: nach jedem sign() ist der SK ein anderer.
- Public Key bleibt konstant.
- Verbleibende-Signaturen-Counter sinkt monoton.
- sigs_remaining() vor und nach sign() unterscheiden sich um genau 1.
- WOTS+-Index in der Signatur (RFC 8391: erste 4 Bytes) progrediert
  monoton.
- Reuse-Detektion: zwei Signaturen mit demselben SK-Snapshot haben
  IDENTISCHEN Index in den ersten 4 Bytes - das ist genau das
  Reuse-Problem aus Demo 2.
- Wenn man den 'alten' SK (aus dem Backup-Szenario) wiederverwendet,
  verifizieren beide Signaturen unter demselben PK.
- Erschoepfung: keinen Test mit 1024 Signaturen (zu langsam fuer Tests),
  aber wir pruefen, dass remaining_signatures bei Set 2^10 mit 1024
  startet.
- Negative Tests: ungueltige Parametersets, kaputter Reset-Versuch.

Ich verzichte BEWUSST auf einen Test, der den Pool komplett leert -
2^10 = 1024 sign-Aufrufe sind als Unit-Test zu schwer. In einem
Integration-Test (separat markiert) waere das machbar.
"""
from __future__ import annotations
import pytest

from src.algorithms import XMSSScheme, XMSSNotEnabledError
from .conftest import needs_xmss


# Alle Tests in diesem Modul brauchen XMSS.
pytestmark = needs_xmss


# ----------------------------------------------------------------------
# Helfer: Index aus einer XMSS-Signatur extrahieren
# ----------------------------------------------------------------------

def signature_index(sig: bytes) -> int:
    """Liest den Index-Teil aus einer XMSS-Signatur.

    Laut RFC 8391, Section 4.1.8:
        Signature ::= idx_sig || r || (sig_ots, auth)
    wobei idx_sig die ersten 4 Bytes (big-endian) sind.

    Das ist DAS Werkzeug fuer Reuse-Detektion: wenn zwei Signaturen
    denselben Index haben, ist State verletzt.
    """
    return int.from_bytes(sig[:4], "big")


# ======================================================================
# Index-Progression
# ======================================================================

class TestIndexProgression:
    def test_secret_key_changes_after_sign(self, xmss_scheme, xmss_keypair, msg):
        """Stateful-Vertrag: sk_after != sk_before."""
        sk_before = xmss_keypair.secret_key
        _, sk_after = xmss_scheme.sign(sk_before, msg)
        assert sk_after != sk_before

    def test_public_key_constant_across_signs(
        self, xmss_scheme, xmss_keypair, msg
    ):
        """PK darf sich NICHT aendern, egal wie oft signiert wird."""
        pk = xmss_keypair.public_key
        sk = xmss_keypair.secret_key
        for _ in range(3):
            _, sk = xmss_scheme.sign(sk, msg)
        # Wir koennen den PK nicht direkt 'extrahieren' nach sign(),
        # aber wir koennen pruefen, dass er weiterhin verifiziert.
        sig, _ = xmss_scheme.sign(sk, msg)
        assert xmss_scheme.verify(pk, msg, sig)

    def test_sk_progression_unique(self, xmss_scheme, xmss_keypair, msg):
        """Die Folge der SKs nach n sign()-Aufrufen muss n+1 verschiedene
        Werte enthalten - kein einziges Duplikat darf vorkommen.
        """
        sk = xmss_keypair.secret_key
        seen = {sk}
        for _ in range(5):
            _, sk = xmss_scheme.sign(sk, msg)
            assert sk not in seen, "SK-Wiederholung waere ein State-Bug!"
            seen.add(sk)


# ======================================================================
# remaining_signatures()
# ======================================================================

class TestRemainingSignatures:
    def test_initial_pool_size(self, xmss_scheme, xmss_keypair):
        """Bei XMSS-SHA2_10_256 startet der Pool bei 2^10 = 1024."""
        remaining = xmss_scheme.remaining_signatures(xmss_keypair.secret_key)
        assert remaining == 1024

    def test_decreases_by_one_per_sign(
        self, xmss_scheme, xmss_keypair, msg
    ):
        """Jedes sign() konsumiert genau einen Index."""
        sk = xmss_keypair.secret_key
        for i in range(1, 6):
            before = xmss_scheme.remaining_signatures(sk)
            _, sk = xmss_scheme.sign(sk, msg)
            after = xmss_scheme.remaining_signatures(sk)
            assert before - after == 1, (
                f"Iteration {i}: {before} -> {after}, "
                f"erwartet wurde Differenz 1"
            )

    def test_monotonically_decreasing(self, xmss_scheme, xmss_keypair, msg):
        """remaining_signatures muss NIE steigen."""
        sk = xmss_keypair.secret_key
        previous = xmss_scheme.remaining_signatures(sk)
        for _ in range(5):
            _, sk = xmss_scheme.sign(sk, msg)
            current = xmss_scheme.remaining_signatures(sk)
            assert current < previous
            previous = current


# ======================================================================
# Index-Feld in der Signatur (RFC 8391)
# ======================================================================

class TestSignatureIndexField:
    def test_first_signature_uses_index_zero(
        self, xmss_scheme, xmss_keypair, msg
    ):
        """Die allererste Signatur unter einem frischen Key nutzt Index 0."""
        sig, _ = xmss_scheme.sign(xmss_keypair.secret_key, msg)
        assert signature_index(sig) == 0

    def test_indices_are_strictly_increasing(
        self, xmss_scheme, xmss_keypair, msg
    ):
        """Aufeinanderfolgende sign-Aufrufe muessen 0, 1, 2, 3, ... liefern."""
        sk = xmss_keypair.secret_key
        indices = []
        for _ in range(5):
            sig, sk = xmss_scheme.sign(sk, msg)
            indices.append(signature_index(sig))
        assert indices == [0, 1, 2, 3, 4]


# ======================================================================
# Reuse-Detektion (Kern der Arbeit)
# ======================================================================

class TestStateReuse:
    """Diese Tests dokumentieren das Reuse-Problem als TESTBARES Verhalten.

    Es ist KEIN Bug-Test sondern ein Beleg: die Tests pruefen, dass
    die Bibliothek genau so kaputtgeht, wie wir es in der Arbeit
    beschreiben. Wenn liboqs in Zukunft eine Reuse-Detektion einbaut
    (z.B. ueber einen geheimen 'used indices' Bitmask im SK), wuerden
    diese Tests fehlschlagen - was dann ein Anlass waere, die
    Diskussion in der Arbeit zu aktualisieren.
    """

    def test_same_sk_snapshot_produces_same_index(
        self, xmss_scheme, xmss_keypair
    ):
        """Wenn ein Angreifer den ALTEN SK in der Hand hat und damit
        eine andere Nachricht signiert, hat seine Signatur denselben
        Index wie unsere legitime Signatur. Genau das ist das
        Wiederverwendungs-Szenario.
        """
        sk_snapshot = xmss_keypair.secret_key
        msg_a = b"legitimate message"
        msg_b = b"forged message - same index"

        sig_a, _ = xmss_scheme.sign(sk_snapshot, msg_a)
        sig_b, _ = xmss_scheme.sign(sk_snapshot, msg_b)

        assert signature_index(sig_a) == signature_index(sig_b) == 0

    def test_reused_signatures_both_verify(
        self, xmss_scheme, xmss_keypair
    ):
        """Beide Signaturen verifizieren unter demselben PK.

        Das ist der eigentliche 'Bruch': die Bibliothek hat keine
        Moeglichkeit zu erkennen, dass eine der beiden Signaturen
        nicht haette existieren duerfen.
        """
        pk = xmss_keypair.public_key
        sk_snapshot = xmss_keypair.secret_key
        msg_a = b"legitimate"
        msg_b = b"forged"

        sig_a, _ = xmss_scheme.sign(sk_snapshot, msg_a)
        sig_b, _ = xmss_scheme.sign(sk_snapshot, msg_b)

        assert xmss_scheme.verify(pk, msg_a, sig_a)
        assert xmss_scheme.verify(pk, msg_b, sig_b)

    def test_reused_signatures_have_different_signature_bytes(
        self, xmss_scheme, xmss_keypair
    ):
        """Die beiden Signaturen unterscheiden sich in den HASH-Ketten,
        nicht im Index. Genau das macht den WOTS+-Forgery-Angriff
        moeglich (siehe Demo 2 / Buchmann et al.).
        """
        sk_snapshot = xmss_keypair.secret_key
        sig_a, _ = xmss_scheme.sign(sk_snapshot, b"msg-a")
        sig_b, _ = xmss_scheme.sign(sk_snapshot, b"msg-b")

        # Index identisch ...
        assert sig_a[:4] == sig_b[:4]
        # ... aber Rest unterschiedlich
        assert sig_a[4:] != sig_b[4:]


# ======================================================================
# Forwarding: SK durch sign() weiterreichen
# ======================================================================

class TestSequentialSigning:
    """Wenn wir den SK korrekt weiterreichen, gibt es KEIN Reuse.

    Das ist die 'positive' Seite der Reuse-Tests: solange der
    Anwender sk_new aus sign() korrekt verwendet, ist alles ok.
    """

    def test_sequential_signing_uses_unique_indices(
        self, xmss_scheme, xmss_keypair, msg
    ):
        sk = xmss_keypair.secret_key
        indices = []
        for _ in range(10):
            sig, sk = xmss_scheme.sign(sk, msg)
            indices.append(signature_index(sig))
        assert len(set(indices)) == len(indices), \
            "Bei korrekt fortgeschriebenem SK darf KEIN Index doppelt vorkommen"

    def test_sequential_signing_all_verify(
        self, xmss_scheme, xmss_keypair, msg
    ):
        pk = xmss_keypair.public_key
        sk = xmss_keypair.secret_key
        for _ in range(10):
            sig, sk = xmss_scheme.sign(sk, msg)
            assert xmss_scheme.verify(pk, msg, sig)


# ======================================================================
# Konstruktor-Validierung
# ======================================================================

class TestXMSSConstruction:
    def test_invalid_parameter_set_raises_valueerror(self):
        """Mit einem unbekannten Parameterset darf XMSSScheme nicht hochkommen."""
        with pytest.raises(ValueError, match="Unbekanntes Parameterset"):
            XMSSScheme("XMSS-SHA2_99_256")

    def test_default_is_smallest(self):
        """Default soll das kleinste Set sein - weil Defaults in Tests
        und Demos genutzt werden und keygen sonst minutenlang dauert.
        """
        scheme = XMSSScheme()
        assert scheme.name == "XMSS-SHA2_10_256"

    def test_is_stateful_property(self, xmss_scheme):
        assert xmss_scheme.is_stateful is True
