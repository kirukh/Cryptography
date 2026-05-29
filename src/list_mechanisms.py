"""
Listet alle in deinem liboqs-Build aktivierten Signatur-Mechanismen.

Aufruf:
    python -m src.list_mechanisms
"""
import oqs


def main():
    print("=" * 60)
    print("liboqs-Diagnose")
    print("=" * 60)

    # Versionen
    try:
        print(f"liboqs C-Library Version : {oqs.oqs_version()}")
    except Exception as e:
        print(f"oqs_version() fehlgeschlagen: {e}")
    try:
        print(f"liboqs-python Version    : {oqs.oqs_python_version()}")
    except Exception as e:
        print(f"oqs_python_version() fehlgeschlagen: {e}")

    # Stateless Sigs (ML-DSA, SPHINCS+, ...)
    print("\n--- Stateless Signatur-Mechanismen ---")
    enabled = oqs.get_enabled_sig_mechanisms()
    if not enabled:
        print("  (keine)")
    else:
        for m in enabled:
            print(f"  {m}")

    # Stateful Sigs (XMSS, LMS)
    print("\n--- Stateful Signatur-Mechanismen ---")
    try:
        enabled_stateful = oqs.get_enabled_stateful_sig_mechanisms()
        if not enabled_stateful:
            print("  (keine)")
        else:
            for m in enabled_stateful:
                print(f"  {m}")
    except AttributeError:
        print("  (liboqs-python kennt keine stateful-Sigs)")

    # Filter: was sieht nach SPHINCS / SLH aus?
    print("\n--- Treffer fuer 'SPHINCS' oder 'SLH' ---")
    matches = [m for m in enabled if "SPHINCS" in m.upper() or "SLH" in m.upper()]
    if not matches:
        print("  (nichts gefunden)")
    else:
        for m in matches:
            print(f"  {m}")


if __name__ == "__main__":
    main()