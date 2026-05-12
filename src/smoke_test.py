"""
Smoke-Test fuer alle drei Algorithmen.

Pruft NUR, ob keygen -> sign -> verify funktioniert.

Aufruf:
    cd pq-bench
    python -m src.smoke_test
"""
from __future__ import annotations
import sys

from .algorithms import (
    MLDSAScheme,
    SLHDSAScheme,
    XMSSScheme,
    XMSSNotEnabledError,
)


def test_scheme(scheme, label: str) -> bool:
    """Fuehrt einen kompletten Roundtrip durch und gibt Status zurueck."""
    print(f"\n=== {label} ===")
    try:
        print(f"  Algorithmus: {scheme.name}")
        print(f"  Stateful:    {scheme.is_stateful}")
        print(f"  PK-Groesse:  {scheme.public_key_size()} Bytes")
        print(f"  SK-Groesse:  {scheme.secret_key_size()} Bytes")
        print(f"  Sig-Groesse: {scheme.signature_size()} Bytes")

        print("  -> keygen ...", end=" ")
        kp = scheme.keygen()
        print("ok")

        message = b"Hallo Post-Quantum-Welt!"
        print("  -> sign ...", end=" ")
        signature, new_sk = scheme.sign(kp.secret_key, message)
        print(f"ok ({len(signature)} Bytes)")

        print("  -> verify ...", end=" ")
        valid = scheme.verify(kp.public_key, message, signature)
        print("ok" if valid else "FEHLGESCHLAGEN")

        print("  -> negativ-verify ...", end=" ")
        invalid = scheme.verify(kp.public_key, message + b"!", signature)
        print("ok" if not invalid else "FEHLGESCHLAGEN")

        if scheme.is_stateful:
            print(f"  -> SK veraendert: {new_sk != kp.secret_key} (muss True sein!)")
            if hasattr(scheme, "remaining_signatures"):
                print(f"  -> verbleibende Signaturen: "
                      f"{scheme.remaining_signatures(new_sk)}")

        return valid and not invalid
    except Exception as e:
        print(f"\n  FEHLER: {type(e).__name__}: {e}")
        return False


def main() -> int:
    results = {}

    results["ML-DSA-65"] = test_scheme(MLDSAScheme("ML-DSA-65"), "ML-DSA-65")

    try:
        results["SLH-DSA-SHA2-128f"] = test_scheme(
            SLHDSAScheme("SLH-DSA-SHA2-128f"), "SLH-DSA-SHA2-128f"
        )
    except Exception as e:
        print(f"\nSLH-DSA konnte nicht initialisiert werden: {e}")
        results["SLH-DSA-SHA2-128f"] = False

    try:
        results["XMSS-SHA2_10_256"] = test_scheme(
            XMSSScheme("XMSS-SHA2_10_256"), "XMSS-SHA2_10_256"
        )
    except XMSSNotEnabledError as e:
        print(f"\n=== XMSS-SHA2_10_256 ===")
        print(f"  XMSS NICHT VERFUEGBAR.\n  {e}")
        results["XMSS-SHA2_10_256"] = None

    print("\n" + "=" * 50)
    print("Zusammenfassung:")
    print("=" * 50)
    for name, ok in results.items():
        status = "OK" if ok is True else ("UEBERSPRUNGEN" if ok is None else "FEHLER")
        print(f"  {name:25s} {status}")

    failed = [n for n, ok in results.items() if ok is False]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
