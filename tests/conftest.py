"""
Gemeinsame pytest-Fixtures fuer das pq-bench-Testset.

Designentscheidungen:
- XMSS-Verfuegbarkeit wird einmal beim Modul-Load gecached.
- Tests, die XMSS brauchen, dekorieren mit @needs_xmss und werden
  uebersprungen statt zu failen, wenn liboqs es nicht enthaelt.
- XMSS-Keypairs werden je Test neu erzeugt (function-scope), damit
  jeder Test einen jungfraeulichen Index-Pool bekommt.
- ML-DSA und SLH-DSA Keypairs sind module-scope (keygen ist nicht ganz
  billig, und stateless => Wiederverwendung ok).
"""
from __future__ import annotations
import pytest

from src.algorithms import (
    MLDSAScheme,
    SLHDSAScheme,
    XMSSScheme,
    XMSSNotEnabledError,
)


# ----------------------------------------------------------------------
# XMSS-Verfuegbarkeit feststellen
# ----------------------------------------------------------------------

def _xmss_available() -> tuple[bool, str]:
    try:
        XMSSScheme("XMSS-SHA2_10_256")
        return True, ""
    except XMSSNotEnabledError as e:
        return False, str(e)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


_XMSS_OK, _XMSS_REASON = _xmss_available()


needs_xmss = pytest.mark.skipif(
    not _XMSS_OK,
    reason=f"XMSS in liboqs nicht aktiviert: {_XMSS_REASON}",
)


# ----------------------------------------------------------------------
# Schema-Fixtures
# ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def mldsa_scheme():
    return MLDSAScheme("ML-DSA-65")


@pytest.fixture(scope="module")
def slhdsa_scheme():
    return SLHDSAScheme("SLH-DSA-SHA2-128f")


@pytest.fixture(scope="module")
def xmss_scheme():
    if not _XMSS_OK:
        pytest.skip(f"XMSS nicht verfuegbar: {_XMSS_REASON}")
    return XMSSScheme("XMSS-SHA2_10_256")


# ----------------------------------------------------------------------
# Schluesselpaar-Fixtures
# ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def mldsa_keypair(mldsa_scheme):
    return mldsa_scheme.keygen()


@pytest.fixture(scope="module")
def slhdsa_keypair(slhdsa_scheme):
    return slhdsa_scheme.keygen()


@pytest.fixture(scope="function")
def xmss_keypair(xmss_scheme):
    """FRISCHES XMSS-Schluesselpaar pro Test - jeder Test bekommt
    einen jungfraeulichen Index-Pool."""
    return xmss_scheme.keygen()


# ----------------------------------------------------------------------
# Test-Konstanten
# ----------------------------------------------------------------------

TEST_MESSAGE = b"pq-bench unit-test message - never reuse in production"
TEST_MESSAGE_ALT = b"a different message for negative tests"


@pytest.fixture
def msg() -> bytes:
    return TEST_MESSAGE


@pytest.fixture
def msg_alt() -> bytes:
    return TEST_MESSAGE_ALT
