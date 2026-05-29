"""
Demo 2 - Index-Wiederverwendung.

Lehrziel: Wenn ein Angreifer einen 'alten' Snapshot des Secret Keys hat,
kann er mit demselben Index erneut signieren. Die Demo zeigt damit
PRAKTISCH die Verletzung der Sicherheitsdefinition (Non-Repudiation,
EUF-CMA) - aber nicht den vollstaendigen Forgery-Angriff.

Was diese Demo zeigt:
    Zwei Signaturen unter demselben Index, beide gueltig unter dem
    gleichen Public Key, fuer zwei VERSCHIEDENE vom Angreifer
    waehlbare Nachrichten. Das verletzt die Sicherheitsdefinition
    eines Signaturverfahrens unmittelbar.

Was diese Demo NICHT zeigt (bewusste Entscheidung):
    Die volle WOTS+-Forgery-Konstruktion, bei der aus zwei
    Signaturen unter demselben Index eine dritte Signatur fuer eine
    bisher noch nicht signierte Nachricht m* konstruiert wird, ohne
    den Secret Key zu kennen. Diese Konstruktion existiert in der
    Literatur (Buchmann/Dahmen/Huelsing 2011, Sec. 3) und folgt aus
    der Tatsache, dass WOTS+-Hash-Ketten bei Reuse teilweise
    'aufgedeckt' werden. Wir verzichten auf die praktische
    Implementierung dieses Schritts; sein Erkenntniswert ueber den
    bereits hier gezeigten Bruch hinaus rechtfertigt den Aufwand im
    Rahmen einer 60h-Projektarbeit nicht.

    Wichtig fuer die Interpretation: bereits die hier gezeigte
    Beobachtung - zwei gueltige Signaturen verschiedener Nachrichten
    unter demselben Index - ist hinreichend, um das Verfahren als
    gebrochen zu betrachten. Die volle Forgery ist eine zusaetzliche
    Folge, kein notwendiger Beleg.

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

    section("Einordnung: was haben wir gezeigt, was nicht?")
    explain("""
        Praktisch gezeigt (Beobachtung):
            Zwei gueltige Signaturen unter demselben Public Key fuer
            denselben Index, aber verschiedene Nachrichten. Das ist
            bereits ein direkter Bruch der Sicherheitsdefinition - ein
            Verifizierer kann nicht zwischen 'legitim' und 'mit altem
            Snapshot nachsigniert' unterscheiden. Non-Repudiation und
            Single-Use sind verletzt.

        Theoretisch bekannt, hier nicht praktisch konstruiert:
            Aus zwei WOTS+-Signaturen unter demselben Index laesst
            sich eine dritte Signatur fuer eine NEUE, bislang nicht
            signierte Nachricht m* berechnen - ohne den Secret Key zu
            besitzen. Die Konstruktion nutzt aus, dass WOTS+ pro
            Index eine Hash-Kette nur bis zu einem bestimmten Schritt
            'aufdeckt'; bei zwei Signaturen liegen oft genug Anker
            offen, um beliebige Zwischenwerte zu kombinieren.

        Referenz: Buchmann, Dahmen, Huelsing - 'XMSS - A Practical
        Forward Secure Signature Scheme', PQCrypto 2011, Sec. 3.

        Fuer die Argumentation dieser Arbeit reicht der bereits
        praktisch demonstrierte Bruch aus: das Sicherheitsmodell von
        XMSS erlaubt keinen Index-Reuse, und der Reuse passiert hier
        ohne Programmierfehler durch ein realistisches Backup-Muster.
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