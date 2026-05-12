"""
Test der Stateless-Eigenschaft fuer ML-DSA und SLH-DSA.

Inhaltlich der wichtige Gegenpart zu test_xmss_stateful.py: bei
stateless-Verfahren MUSS sign() den Secret Key unveraendert
zurueckgeben - sonst koennten wir nicht das gleiche Interface verwenden,
ohne die Aufrufer zu verwirren.
"""
from __future__ import annotations
import pytest

from src.algorithms import MLDSAScheme, SLHDSAScheme


class TestMLDSAStateless:
    def test_secret_key_unchanged_after_sign(
        self, mldsa_scheme, mldsa_keypair, msg
    ):
        sk_before = mldsa_keypair.secret_key
        _, sk_after = mldsa_scheme.sign(sk_before, msg)
        assert sk_after == sk_before

    def test_many_signatures_with_same_key(
        self, mldsa_scheme, mldsa_keypair, msg
    ):
        """Mehrfach-Signing mit demselben SK funktioniert - das ist der
        Vorteil gegenueber XMSS."""
        sk = mldsa_keypair.secret_key
        for _ in range(50):
            sig, sk_new = mldsa_scheme.sign(sk, msg)
            assert mldsa_scheme.verify(mldsa_keypair.public_key, msg, sig)
            assert sk_new == sk

    def test_invalid_parameter_set_raises(self):
        with pytest.raises(ValueError, match="Unbekanntes Parameterset"):
            MLDSAScheme("ML-DSA-999")


class TestSLHDSAStateless:
    def test_secret_key_unchanged_after_sign(
        self, slhdsa_scheme, slhdsa_keypair, msg
    ):
        sk_before = slhdsa_keypair.secret_key
        _, sk_after = slhdsa_scheme.sign(sk_before, msg)
        assert sk_after == sk_before

    def test_multiple_signatures_verify(
        self, slhdsa_scheme, slhdsa_keypair, msg
    ):
        """SLH-DSA-sign ist nicht ganz billig - 5 Iterationen reichen."""
        for _ in range(5):
            sig, _ = slhdsa_scheme.sign(slhdsa_keypair.secret_key, msg)
            assert slhdsa_scheme.verify(
                slhdsa_keypair.public_key, msg, sig
            )

    def test_invalid_parameter_set_raises(self):
        with pytest.raises(ValueError, match="Unbekanntes Parameterset"):
            SLHDSAScheme("SLH-DSA-NOPE")
