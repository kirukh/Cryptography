"""
Gemeinsame pytest-Fixtures fuer das pq-bench-Testset.

Designentscheidungen:
- Wir importieren oqs nur einmal hier und cachen den Status, ob XMSS
  in diesem Build aktiviert ist. Sonst bekommen wir bei jedem Test mit
  XMSS einen Import-Fehler.
- Wir bieten ein 'small_xmss_scheme'-Fixture mit dem kleinsten Para-
  meterset (2^10), weil keygen mit 2^16 oder 2^20 fuer eine Test-Suite
  zu langsam waere.
- Schluesselpaare werden je Test neu erzeugt - keygen ist bei XMSS-2^10
  zwar nicht billig (~Sekunde), aber die Tests bleiben dadurch isoliert.
- module-scope-Fixtures fuer SLH-DSA-keygen, weil das ebenfalls langsam
  ist und wir bei SLH-DSA-Tests nicht den Schluessel selbst, sondern
  das Wrapper-Verhalten testen.
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
    """Prueft, ob XMSS in diesem liboqs-Build aktiv ist.

    Returns:
        (verfuegbar, grund_falls_nicht)
    """
    try:
        XMSSScheme("XMSS-SHA2_10_256")
        return True, ""
    except XMSSNotEnabledError as e:
        return False, str(e)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


_XMSS_OK, _XMSS_REASON = _xmss_available()


# Reusable Skip-Marker. Tests, die XMSS brauchen, dekorieren mit
# @needs_xmss; sie werden uebersprungen statt zu failen, wenn der
# liboqs-Build XMSS nicht enthaelt.
needs_xmss = pytest.mark.skipif(
    not _XMSS_OK,
    reason=f"XMSS in liboqs nicht aktiviert: {_XMSS_REASON}",
)


# ----------------------------------------------------------------------
# Schema-Fixtures
# ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def mldsa_scheme():
    """ML-DSA-65 Wrapper-Instanz."""
    return MLDSAScheme("ML-DSA-65")


@pytest.fixture(scope="module")
def slhdsa_scheme():
    """SLH-DSA-SHA2-128f Wrapper-Instanz.

    Wir nehmen die '-f'-Variante, weil sie etwas schneller signiert
    als '-s' - bei kleinerer 128-Bit-Sicherheit reicht das fuer Tests.
    """
    return SLHDSAScheme("SLH-DSA-SHA2-128f")


@pytest.fixture(scope="module")
def xmss_scheme():
    """XMSS-SHA2_10_256 (kleinstes Set, schnelles keygen)."""
    if not _XMSS_OK:
        pytest.skip(f"XMSS nicht verfuegbar: {_XMSS_REASON}")
    return XMSSScheme("XMSS-SHA2_10_256")


# ----------------------------------------------------------------------
# Schluesselpaar-Fixtures
# ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def mldsa_keypair(mldsa_scheme):
    """Ein ML-DSA-Schluesselpaar pro Test-Modul.

    Stateless => kann ueber alle Tests im Modul wiederverwendet werden.
    """
    return mldsa_scheme.keygen()


@pytest.fixture(scope="module")
def slhdsa_keypair(slhdsa_scheme):
    """Ein SLH-DSA-Schluesselpaar pro Test-Modul.

    Stateless => Wiederverwendung ist ok und spart Zeit (keygen kostet).
    """
    return slhdsa_scheme.keygen()


@pytest.fixture(scope="function")
def xmss_keypair(xmss_scheme):
    """FRISCHES XMSS-Schluesselpaar pro Test.

    Bewusst function-scope: jeder XMSS-Test bekommt einen 'jungfraeu-
    lichen' Index-Pool. Sonst koennten Tests sich gegenseitig den Pool
    leeren oder Reihenfolgen-Abhaengigkeiten erzeugen.
    """
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
