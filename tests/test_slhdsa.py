"""
SLH-DSA-spezifische Tests.

Wir pruefen:
- Stateless-Verhalten (analog zu ML-DSA).
- Friendly-Name -> liboqs-Name-Mapping ist korrekt verdrahtet
  (also: was wir 'SLH-DSA-SHA2-128f' nennen, ist auch wirklich
  das, was unter SLH_DSA_PURE_SHA2_128F daherkommt).
- s/f-Varianten haben unterschiedliche Signaturgroessen
  ('s' = small signatures, 'f' = fast signing -> larger sigs).
- Hoehere Security-Level haben groessere Schluessel.

Hinweis zu Performance:
    SLH-DSA-keygen ist relativ schnell, sign() bei -s-Varianten ist
    aber langsam. Wir bleiben deshalb auf -128f bei den Roundtrip-
    Tests und nutzen die anderen Sets nur fuer Groessenvergleiche
    ohne sign().
"""
from __future__ import annotations
import pytest

from src.algorithms import SLHDSAScheme, SPHINCSScheme


class TestSLHDSAStateless:
    def test_secret_key_unchanged_after_sign(
        self, slhdsa_scheme, slhdsa_keypair, msg
    ):
        sk_before = slhdsa_keypair.secret_key
        _, sk_after = slhdsa_scheme.sign(sk_before, msg)
        assert sk_after == sk_before

    def test_multiple_signatures_verify(self, slhdsa_scheme, slhdsa_keypair, msg):
        """SLH-DSA-sign ist nicht ganz billig - wir machen nur 5 Iterationen."""
        for _ in range(5):
            sig, _ = slhdsa_scheme.sign(slhdsa_keypair.secret_key, msg)
            assert slhdsa_scheme.verify(slhdsa_keypair.public_key, msg, sig)


class TestSLHDSANaming:
    def test_sphincs_alias_is_slhdsa(self):
        """SPHINCSScheme muss ein Alias auf SLHDSAScheme sein.

        Damit aelterer Code mit 'SPHINCSScheme' weiterhin funktioniert.
        """
        assert SPHINCSScheme is SLHDSAScheme

    def test_friendly_name_preserved(self):
        scheme = SLHDSAScheme("SLH-DSA-SHA2-128f")
        assert scheme.name == "SLH-DSA-SHA2-128f"

    def test_invalid_parameter_set_raises(self):
        with pytest.raises(ValueError, match="Unbekanntes Parameterset"):
            SLHDSAScheme("SLH-DSA-NOPE")


class TestSLHDSAParameterRelations:
    """Strukturelle Eigenschaften der Parametrisierung.

    Diese Tests pruefen NICHT, dass die Werte exakt mit FIPS 205
    uebereinstimmen, sondern nur die Relationen zwischen den Sets.
    Das schuetzt vor Mapping-Bugs (z.B. wenn jemand versehentlich
    die Eintraege in PARAMETER_SETS vertauscht).
    """

    def test_f_variants_have_larger_signatures_than_s(self):
        """'f' (fast) hat grossere Signaturen als 's' (small)."""
        s = SLHDSAScheme("SLH-DSA-SHA2-128s")
        f = SLHDSAScheme("SLH-DSA-SHA2-128f")
        assert f.signature_size() > s.signature_size()

    def test_higher_security_level_has_larger_signature(self):
        s128 = SLHDSAScheme("SLH-DSA-SHA2-128f")
        s256 = SLHDSAScheme("SLH-DSA-SHA2-256f")
        assert s256.signature_size() > s128.signature_size()
        assert s256.public_key_size() > s128.public_key_size()

    @pytest.mark.parametrize("param_set", [
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    ])
    def test_sha2_variants_instantiable(self, param_set):
        scheme = SLHDSAScheme(param_set)
        assert scheme.signature_size() > 0
        assert scheme.public_key_size() > 0
