"""
Demo 2 - Index-Wiederverwendung.

Lehrziel: Wenn ein Angreifer einen 'alten' Snapshot des Secret Keys hat,
kann er mit demselben Index erneut signieren.

WICHTIG zur Tragweite:
    Wir zeigen, dass beide Signaturen (mit demselben Index, aber
    unterschiedlichen Nachrichten) gegen denselben Public Key
    verifizieren. Das allein verletzt die Sicherheitsdefinition
    (Non-Repudiation, Unforgeability).

    Die theoretische Folge - WOTS+-Forgery - ist deutlich
    aufwaendiger zu demonstrieren: aus zwei Signaturen unter demselben
    WOTS+-Key-Index laesst sich ein 'Mix' der Hash-Ketten konstruieren,
    der eine VOELLIG NEUE Nachricht authentisiert. Das setzen wir nicht
    praktisch um, erklaeren es aber didaktisch.

    Quelle: Buchmann/Dahmen/Huelsing, 'XMSS - A Practical Forward
    Secure Signature Scheme', PQCrypto 2011, Sec. 3.

Aufruf:
    python -m src.stateful_demo.demo02_reuse_attack
"""
from src.algorithms import XMSSScheme
from src.stateful_demo._console import (
    banner, section, info, bad, warn, explain,
    show_bytes, takeaway,
)


def main():
    banner("Demo 2: Index-Wiederverwendung (das Kardinal-Problem)")

    explain("""
        Wir simulieren eine klassische Fehlnutzung: Eine Anwendung
        besitzt einen XMSS-Secret-Key. Ein Snapshot wird (z.B. vor
        einer Wartungsarbeit) gesichert. Anschliessend wird ein paar
        Mal signiert. Spaeter wird der ALTE Snapshot wieder geladen
        - sei es durch einen Restore, ein VM-Snapshot-Rollback, oder
        einen Programmierfehler. Jetzt steht der Index wieder dort,
        wo er Stunden vorher schon war.
    """)

    scheme = XMSSScheme("XMSS-SHA2_10_256")

    section("Setup: ein Schluesselpaar, ein 'Snapshot'")
    kp = scheme.keygen()
    pk = kp.public_key
    sk_initial = kp.secret_key   # <-- DAS ist unser 'Backup'
    info("Initialer SK gespeichert (=Backup-Snapshot)")
    show_bytes("PK", pk)
    show_bytes("SK (snapshot)", sk_initial, show_first=24)

    section("Normaler Betrieb: ein paar legitime Signaturen")
    sk = sk_initial
    for i, msg in enumerate([b"legit-1", b"legit-2", b"legit-3"]):
        sig, sk = scheme.sign(sk, msg)
        info(f"  Sig {i+1}: msg={msg!r:12s} -> "
             f"verifiziert={scheme.verify(pk, msg, sig)}")
    info(f"  Aktueller Stand: {scheme.remaining_signatures(sk)} "
         f"Signaturen verbleibend")

    section("Der Fehler: Backup wird wiederhergestellt")
    explain("""
        Aus Sicht des Systems ist nichts auffaellig - die SK-Datei wird
        einfach zurueckgespielt. Verschiedene reale Ursachen koennten
        das ausloesen: VM-Snapshot-Restore, Rsync-Replikation, manuelles
        cp eines Backups, Container-Restart von einem alten Image, ...
    """)

    sk_restored = sk_initial   # boese: alter Snapshot wieder aktiv
    info("SK wird auf den Backup-Stand zurueckgesetzt:")
    info(f"  remaining nach Restore: {scheme.remaining_signatures(sk_restored)}")
    warn("Der Index ist jetzt ZURUECKGESETZT auf den Stand vor 3 Signaturen!")

    section("Die Konsequenz: 'neue' Signaturen mit altem Index")
    explain("""
        Wir signieren jetzt eine voellig andere Nachricht mit dem
        wiederhergestellten Snapshot. XMSS hat keine Moeglichkeit, das
        zu erkennen - es macht einfach seinen Job.
    """)

    msg_a = b"Original message - signed correctly"
    msg_b = b"FORGED  message - same index reused"

    sig_a, _ = scheme.sign(sk_initial, msg_a)
    sig_b, _ = scheme.sign(sk_restored, msg_b)

    info(f"\n  Signatur A: msg={msg_a!r}")
    show_bytes("    sig_a", sig_a)
    info(f"  Signatur B: msg={msg_b!r}")
    show_bytes("    sig_b", sig_b)

    # In RFC 8391 ist der Index die ersten 4 Bytes der Signatur.
    idx_a = int.from_bytes(sig_a[:4], "big")
    idx_b = int.from_bytes(sig_b[:4], "big")
    info(f"\n  Index in sig_a:   {idx_a}")
    info(f"  Index in sig_b:   {idx_b}")
    if idx_a == idx_b:
        bad(f"BEIDE Signaturen verwenden denselben Index {idx_a}!")
    else:
        warn("Indizes unterschiedlich - bitte pruefen.")

    section("Verifikation: beide Signaturen sind 'gueltig'")
    valid_a = scheme.verify(pk, msg_a, sig_a)
    valid_b = scheme.verify(pk, msg_b, sig_b)
    info(f"  verify(pk, msg_a, sig_a) = {valid_a}")
    info(f"  verify(pk, msg_b, sig_b) = {valid_b}")
    if valid_a and valid_b:
        bad("Aus Sicht eines Verifizierers: BEIDES gueltig.")
        bad("Non-Repudiation und Single-Use sind gebrochen.")

    section("Was bedeutet das kryptographisch?")
    explain("""
        Beobachtung 1 - bereits problematisch:
            Es existieren ZWEI gueltige Signaturen unter demselben
            Public Key fuer den gleichen Index, aber verschiedene
            Nachrichten. Das verletzt die Non-Repudiation.

        Beobachtung 2 - schwerwiegender:
            Aus zwei WOTS+-Signaturen mit demselben Index laesst sich
            ein Angriff konstruieren, der eine NEUE, vom Angreifer
            gewaehlte Nachricht m* signieren kann - ohne den Secret
            Key zu kennen. Die Sicherheit von WOTS+ basiert auf der
            Annahme, dass jeder Hash-Ketten-Anker GENAU EINMAL
            'aufgedeckt' wird.
    """)

    takeaway("""
        XMSS bricht NICHT durch kryptanalytische Schwaeche. Es bricht
        durch eine Verletzung des Modells: das Modell setzt zwingend
        voraus, dass jeder Index genau einmal verwendet wird. Diese
        Garantie kann ein Algorithmus selbst nicht erzwingen - sie
        muss vom UMGEBENDEN SYSTEM (Storage, Backup-Strategie,
        Nebenlaeufigkeit) sichergestellt werden.
    """)


if __name__ == "__main__":
    main()
