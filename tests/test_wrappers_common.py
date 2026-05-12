"""
Tests, die fuer ALLE drei Wrapper gleichzeitig gelten.

Wir parametrisieren ueber ein 'scheme'-Fixture, das nacheinander
ML-DSA, SLH-DSA und XMSS einliefert. So entstehen pro Test drei
Test-Cases mit minimalem Code-Duplikat.

Wir testen hier das gemeinsame Interface aus base.py:
- keygen erzeugt sinnvolle PK/SK
- sign liefert (signature, updated_secret_key)
- verify akzeptiert eigene Signaturen
- verify lehnt manipulierte Signaturen / Nachrichten / fremde PKs ab
- Groessenangaben stimmen mit tatsaechlichen Outputs ueberein
- name und is_stateful sind sinnvolle Werte
"""
from __future__ import annotations
import pytest

from src.algorithms import (
    SignatureScheme,
    KeyPair,
    MLDSAScheme,
    SLHDSAScheme,
    XMSSScheme,
)
from .conftest import needs_xmss


ALL_SCHEMES = [
    pytest.param(lambda: MLDSAScheme("ML-DSA-65"), id="ML-DSA-65"),
    pytest.param(
        lambda: SLHDSAScheme("SLH-DSA-SHA2-128f"), id="SLH-DSA-SHA2-128f"
    ),
    pytest.param(
        lambda: XMSSScheme("XMSS-SHA2_10_256"),
        id="XMSS-SHA2_10_256",
        marks=needs_xmss,
    ),
]


@pytest.fixture(params=ALL_SCHEMES)
def scheme(request) -> SignatureScheme:
    factory = request.param
    return factory()


# ======================================================================
# Schluesselgenerierung
# ======================================================================

class TestKeygen:
    def test_keygen_returns_keypair(self, scheme):
        kp = scheme.keygen()
        assert isinstance(kp, KeyPair)

    def test_keygen_keys_are_bytes(self, scheme):
        kp = scheme.keygen()
        assert isinstance(kp.public_key, (bytes, bytearray))
        assert isinstance(kp.secret_key, (bytes, bytearray))

    def test_keygen_keys_are_nonempty(self, scheme):
        kp = scheme.keygen()
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_keygen_metadata_filled(self, scheme):
        kp = scheme.keygen()
        assert kp.algorithm
        assert kp.parameter_set == scheme.name

    def test_keygen_two_calls_yield_different_keys(self, scheme):
        """Zwei keygen-Aufrufe muessen unabhaengige Schluessel liefern."""
        kp1 = scheme.keygen()
        kp2 = scheme.keygen()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key


# ======================================================================
# Groessenangaben
# ======================================================================

class TestSizes:
    def test_public_key_size_matches(self, scheme):
        kp = scheme.keygen()
        assert len(kp.public_key) == scheme.public_key_size()

    def test_secret_key_size_matches(self, scheme):
        kp = scheme.keygen()
        assert len(kp.secret_key) == scheme.secret_key_size()

    def test_signature_size_matches(self, scheme, msg):
        kp = scheme.keygen()
        sig, _ = scheme.sign(kp.secret_key, msg)
        assert len(sig) == scheme.signature_size()

    def test_sizes_are_positive_integers(self, scheme):
        for s in (scheme.public_key_size(),
                  scheme.secret_key_size(),
                  scheme.signature_size()):
            assert isinstance(s, int)
            assert s > 0


# ======================================================================
# Sign / Verify Roundtrip
# ======================================================================

class TestSignVerify:
    def test_roundtrip(self, scheme, msg):
        kp = scheme.keygen()
        sig, _ = scheme.sign(kp.secret_key, msg)
        assert scheme.verify(kp.public_key, msg, sig) is True

    def test_signature_is_bytes(self, scheme, msg):
        kp = scheme.keygen()
        sig, _ = scheme.sign(kp.secret_key, msg)
        assert isinstance(sig, (bytes, bytearray))
        assert len(sig) > 0

    def test_sign_returns_tuple(self, scheme, msg):
        """sign() muss IMMER (sig, sk) liefern - bei stateful UND
        stateless. Sonst koennen wir die beiden Faelle nicht
        einheitlich aufrufen."""
        kp = scheme.keygen()
        result = scheme.sign(kp.secret_key, msg)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_verify_rejects_modified_message(self, scheme, msg, msg_alt):
        kp = scheme.keygen()
        sig, _ = scheme.sign(kp.secret_key, msg)
        assert scheme.verify(kp.public_key, msg_alt, sig) is False

    def test_verify_rejects_modified_signature(self, scheme, msg):
        kp = scheme.keygen()
        sig, _ = scheme.sign(kp.secret_key, msg)
        tampered = bytearray(sig)
        tampered[-1] ^= 0x01
        assert scheme.verify(kp.public_key, msg, bytes(tampered)) is False

    def test_verify_rejects_foreign_public_key(self, scheme, msg):
        """Signatur unter pk1 darf nicht unter pk2 verifizieren."""
        kp1 = scheme.keygen()
        kp2 = scheme.keygen()
        sig, _ = scheme.sign(kp1.secret_key, msg)
        assert scheme.verify(kp2.public_key, msg, sig) is False

    def test_verify_rejects_empty_signature(self, scheme, msg):
        """Leere Signatur darf nicht akzeptiert werden."""
        kp = scheme.keygen()
        try:
            result = scheme.verify(kp.public_key, msg, b"")
        except Exception:
            return  # Exception ist auch ok
        assert result is False


# ======================================================================
# Interface-Eigenschaften
# ======================================================================

class TestInterface:
    def test_name_is_string(self, scheme):
        assert isinstance(scheme.name, str)
        assert len(scheme.name) > 0

    def test_is_stateful_is_bool(self, scheme):
        assert isinstance(scheme.is_stateful, bool)

    def test_xmss_is_stateful_others_arent(self, scheme):
        """XMSS muss stateful sein, ML-DSA und SLH-DSA nicht."""
        if "XMSS" in scheme.name:
            assert scheme.is_stateful is True
        else:
            assert scheme.is_stateful is False
