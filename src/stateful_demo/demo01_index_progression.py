"""
Demo 1 - Index-Progression.

Lehrziel: Verstaendnis des grundlegenden Stateful-Mechanismus.
- Jede Signatur verbraucht genau einen Index.
- Der Secret-Key veraendert sich nach jedem Signieren.
- Der Public Key bleibt konstant.
- Der Pool ist endlich und nicht regenerierbar.

Aufruf:
    python -m src.stateful_demo.demo01_index_progression
"""
from src.algorithms import XMSSScheme
from src.stateful_demo._console import (
    banner, section, info, good, warn, explain,
    show_bytes, fingerprint, takeaway,
)


def main():
    banner("Demo 1: XMSS Index-Progression")

    explain("""
        XMSS ist eine 'stateful' Signatur. Der Secret Key enthaelt
        einen Index, der angibt welcher One-Time-Key (genauer: WOTS+-
        Schluessel) als naechstes verwendet wird. Nach jedem sign()
        muss dieser Index inkrementiert werden - sonst entsteht eine
        gefaehrliche Wiederverwendung. Diese Demo zeigt das Verhalten
        an einem konkreten Beispiel.
    """)

    # Wir nehmen das kleine Set: 2^10 = 1024 Signaturen.
    section("Schluesselgenerierung")
    scheme = XMSSScheme("XMSS-SHA2_10_256")
    info(f"Parameterset: {scheme.name}")
    info(f"Theoretischer Pool: 2^10 = 1024 Signaturen")

    kp = scheme.keygen()
    show_bytes("Public Key", kp.public_key)
    show_bytes("Secret Key (initial)", kp.secret_key, show_first=24)
    info(f"Verbleibende Signaturen: {scheme.remaining_signatures(kp.secret_key)}")

    # Wir signieren drei verschiedene Nachrichten und beobachten den State.
    section("Drei Signaturen, drei verschiedene States")

    pk = kp.public_key       # bleibt konstant
    sk = kp.secret_key       # wird nach jedem sign() aktualisiert
    pk_fp_initial = fingerprint(pk)

    messages = [
        b"Erste Nachricht  - 'Hallo Welt'",
        b"Zweite Nachricht - 'Foo Bar'",
        b"Dritte Nachricht - 'Lorem Ipsum'",
    ]

    for i, msg in enumerate(messages):
        info(f"\n  Iteration {i+1}: signiere '{msg.decode()}'")

        # Vor dem Signieren: aktueller State
        sk_before_fp = fingerprint(sk)
        remaining_before = scheme.remaining_signatures(sk)

        # Signieren - Achtung: scheme.sign() gibt den AKTUALISIERTEN sk zurueck!
        signature, sk_new = scheme.sign(sk, msg)
        sk_after_fp = fingerprint(sk_new)
        remaining_after = scheme.remaining_signatures(sk_new)

        info(f"    SK vor Sign:    sha256={sk_before_fp}  "
             f"verbleibend={remaining_before}")
        info(f"    SK nach Sign:   sha256={sk_after_fp}  "
             f"verbleibend={remaining_after}")
        info(f"    Sig-Fingerprint: sha256={fingerprint(signature)}  "
             f"len={len(signature)}")

        # Verify funktioniert immer mit demselben PK!
        if scheme.verify(pk, msg, signature):
            good(f"    Signatur ist gueltig (verifiziert mit PK)")
        else:
            warn(f"    Verifikation fehlgeschlagen!")

        # SK fuer naechsten Durchgang uebernehmen
        sk = sk_new

    # Beobachtung: PK ist immer noch derselbe.
    section("Konstanz des Public Keys")
    pk_fp_final = fingerprint(pk)
    info(f"PK Fingerprint initial: {pk_fp_initial}")
    info(f"PK Fingerprint final:   {pk_fp_final}")
    if pk_fp_initial == pk_fp_final:
        good("Public Key ist unveraendert - das muss so sein.")
    else:
        warn("Public Key veraendert?! - das waere ein Bug.")

    section("Zusammenfassung")
    final_remaining = scheme.remaining_signatures(sk)
    info(f"Verbleibende Signaturen mit diesem Key: {final_remaining}")
    info(f"Verbrauchte Indizes:                    {1024 - final_remaining}")

    takeaway("""
        Der State ist NICHT der Secret Key allein, sondern der
        (Secret-Key, Index)-Verbund. Wenn der Anwender den 'alten' SK
        (vor sign) speichert und ihn erneut zum Signieren nutzt,
        wird ein bereits verbrauchter Index wiederverwendet.
        Genau das demonstriert Demo 2.
    """)


if __name__ == "__main__":
    main()
