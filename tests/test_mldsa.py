"""
ML-DSA-spezifische Tests.

Was hier geprueft wird:
- Stateless-Eigenschaft: sign() darf den SK NICHT veraendern.
- Mehrfach-Signing mit demselben SK funktioniert (das ist der ganze
  Vorteil gegenueber XMSS).
- Mehrere Parametersets sind instanziierbar (44, 65, 87).
- Ungueltige Parametersets werfen ValueError.
"""
from __future__ import annotations
import pytest

from src.algorithms import MLDSAScheme


class TestMLDSAStateless:
    def test_secret_key_unchanged_after_sign(self, mldsa_scheme, mldsa_keypair, msg):
        """Bei stateless-Verfahren muss der zurueckgegebene SK identisch sein.

        Das ist der Vertrag von base.py: bei stateless ist
        updated_secret_key == secret_key.
        """
        sk_before = mldsa_keypair.secret_key
        _, sk_after = mldsa_scheme.sign(sk_before, msg)
        assert sk_after == sk_before

    def test_many_signatures_with_same_key(self, mldsa_scheme, mldsa_keypair, msg):
        """100 Signaturen mit demselben SK - alle verifizieren."""
        sk = mldsa_keypair.secret_key
        for i in range(100):
            sig, sk_new = mldsa_scheme.sign(sk, msg)
            assert mldsa_scheme.verify(mldsa_keypair.public_key, msg, sig)
            # Stateless => sk darf sich ueber die Iterationen nicht aendern
            assert sk_new == sk

    def test_signatures_can_differ_or_match(self, mldsa_scheme, mldsa_keypair, msg):
        """ML-DSA in liboqs ist deterministisch (FIPS 204 Default-Modus).

        Wir pruefen, dass zwei Signaturen entweder gleich oder
        verschieden sein DUERFEN - aber beide muessen verifizieren.
        Wir machen das absichtlich nicht zu strikt, weil der Modus
        (deterministic vs. randomized) je nach liboqs-Build variieren
        kann.
        """
        sig1, _ = mldsa_scheme.sign(mldsa_keypair.secret_key, msg)
        sig2, _ = mldsa_scheme.sign(mldsa_keypair.secret_key, msg)
        assert mldsa_scheme.verify(mldsa_keypair.public_key, msg, sig1)
        assert mldsa_scheme.verify(mldsa_keypair.public_key, msg, sig2)


class TestMLDSAParameterSets:
    @pytest.mark.parametrize("param_set", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_all_parameter_sets_instantiable(self, param_set):
        scheme = MLDSAScheme(param_set)
        assert scheme.name == param_set
        assert scheme.is_stateful is False

    def test_higher_security_levels_have_larger_keys(self):
        """ML-DSA-87 sollte groessere Keys/Sigs haben als ML-DSA-44."""
        s44 = MLDSAScheme("ML-DSA-44")
        s87 = MLDSAScheme("ML-DSA-87")
        assert s87.public_key_size() > s44.public_key_size()
        assert s87.signature_size() > s44.signature_size()

    def test_invalid_parameter_set_raises(self):
        with pytest.raises(ValueError, match="Unbekanntes Parameterset"):
            MLDSAScheme("ML-DSA-999")
