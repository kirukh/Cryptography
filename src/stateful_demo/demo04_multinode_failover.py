"""
Demo 4 - Multi-Node-Failover.

Lehrziel: Auch wenn alles 'sauber' programmiert ist und Backups korrekt
laufen - sobald MEHR ALS EIN Knoten dasselbe Schluesselmaterial besitzt,
ist die Stateful-Garantie systematisch unmoeglich ohne Synchronisation
und globale Sperre.

Wir simulieren zwei realistische Szenarien:

  Scenario A: Active-Active Cluster mit shared Storage
              Beide Knoten lesen denselben SK-File. Race Condition
              fuehrt zur Index-Wiederverwendung.

  Scenario B: Active-Standby mit asynchroner Replikation
              Standby-Knoten uebernimmt nach Failover, hat aber
              einen aelteren Stand des SK.

Methodischer Hinweis zu Scenario A:
    Wir reproduzieren KEINE echte Race Condition (die waere
    nicht-deterministisch und unzuverlaessig zu zeigen). Stattdessen
    konstruieren wir den deterministisch erzeugbaren ENDZUSTAND, den
    eine verlorene Read-Modify-Write-Sequenz hinterlassen wuerde:
    beide Knoten haben unabhaengig vom selben SK-Snapshot signiert,
    bevor einer von ihnen seinen aktualisierten Stand zurueckschreibt.
    Das Beobachtungs-Ergebnis ist identisch mit dem einer echten Race;
    der Unterschied liegt nur im Zustandekommen. Diese Vereinfachung
    macht die Demo reproduzierbar, ohne die kryptographische Aussage
    zu veraendern.

Aufruf:
    python -m src.stateful_demo.demo04_multinode_failover
"""
from src.algorithms import XMSSScheme
from src.stateful_demo._console import (
    banner, section, info, good, bad, warn, explain,
    fingerprint, takeaway,
)


def main():
    banner("Demo 4: Multi-Node-Failover (Cluster-Probleme)")

    explain("""
        Klassische Hochverfuegbarkeits-Patterns gehen davon aus, dass
        Anwendungs-State in einer Datenbank oder einem KV-Store liegt
        und Knoten auf Anwendungsebene zustandslos sind. Bei XMSS
        bricht das fundamental: der Schluessel SELBST ist State.
    """)

    scheme = XMSSScheme("XMSS-SHA2_10_256")
    kp = scheme.keygen()
    pk = kp.public_key

    # ============================================================
    # Scenario A: Active-Active Cluster mit Shared Storage
    # ============================================================
    section("Scenario A: Active-Active mit Shared Storage")
    explain("""
        Zwei Knoten Node1 und Node2 teilen sich einen NFS-Mount, auf
        dem die SK-Datei liegt. Beide Knoten lesen den SK, beide
        signieren parallel, beide schreiben zurueck. Klassische
        Race-Condition - aber gemeiner als bei einer DB, weil
        File-Locks auf NFS unzuverlaessig sind und ein Read-Modify-
        Write hier kryptographische Sicherheit kostet.
    """)
    explain("""
        Methodisch: wir loesen die Race nicht aus, sondern stellen ihren
        Endzustand deterministisch her - beide Knoten signieren vom
        gleichen SK-Snapshot. Das entspricht exakt der Beobachtung, die
        ein Operator nach einer fehlgeschlagenen Read-Modify-Write-
        Sequenz machen wuerde.
    """)

    sk_shared = kp.secret_key
    initial_idx = 1024 - scheme.remaining_signatures(sk_shared)
    info(f"Beide Knoten lesen SK ein (sha256={fingerprint(sk_shared)})")
    info(f"Index laut Filesystem: {initial_idx}")

    info("\n  Konstruktion des Race-Endzustands:")
    info("  Beide Knoten signieren vom SELBEN SK-Snapshot - so als waere")
    info("  zwischen ihren Read- und Write-Operationen kein Lock gehalten")
    info("  worden.")
    msg_node1 = b"Node1: process payment $1000"
    msg_node2 = b"Node2: process payment $50"

    sig_node1, _ = scheme.sign(sk_shared, msg_node1)
    sig_node2, _ = scheme.sign(sk_shared, msg_node2)

    idx_n1 = int.from_bytes(sig_node1[:4], "big")
    idx_n2 = int.from_bytes(sig_node2[:4], "big")
    info(f"  Node1 signiert msg1, erhaelt Index {idx_n1}")
    info(f"  Node2 signiert msg2, erhaelt Index {idx_n2}")

    if idx_n1 == idx_n2:
        bad(f"  Beide haben Index {idx_n1} verwendet. Reuse!")
        info(f"  verify(pk, msg1, sig1) = "
             f"{scheme.verify(pk, msg_node1, sig_node1)}")
        info(f"  verify(pk, msg2, sig2) = "
             f"{scheme.verify(pk, msg_node2, sig_node2)}")

    explain("""
        Selbst mit File-Locks: das Locking macht den Cluster effektiv
        wieder seriell - du kannst nicht zwei Knoten unabhaengig
        signieren lassen. Damit ist der Vorteil eines Active-Active-
        Setups dahin.
    """)

    # ============================================================
    # Scenario B: Active-Standby mit asynchroner Replikation
    # ============================================================
    section("Scenario B: Active-Standby mit asynchroner Replikation")
    explain("""
        Klassisches HA-Setup: ein aktiver Knoten signiert, sein State
        wird asynchron zu einem Standby gespiegelt. Wenn der Active
        ausfaellt, uebernimmt der Standby. Bei DB-Replikation
        funktioniert das (man verliert die letzten Sekunden Daten, ok).
        Bei XMSS verliert man Schluesselmaterial-Konsistenz.
    """)

    kp2 = scheme.keygen()

    sk_active = kp2.secret_key
    sk_standby = kp2.secret_key   # initial im Sync

    info("\n  Phase 1: alles in Sync")
    for msg in [b"sync-1", b"sync-2"]:
        _, sk_active = scheme.sign(sk_active, msg)
        sk_standby = sk_active   # synchroner Replikations-Catchup
    info(f"  Active SK : sha256={fingerprint(sk_active)}")
    info(f"  Standby SK: sha256={fingerprint(sk_standby)}")
    good("  In Sync.")

    info("\n  Phase 2: Replikations-Lag (Standby haengt 2 Operationen "
         "hinterher)")
    sk_active_pre_lag = sk_active
    for msg in [b"async-payment-1", b"async-payment-2"]:
        _, sk_active = scheme.sign(sk_active, msg)
    sk_standby = sk_active_pre_lag
    warn(f"  Active SK : sha256={fingerprint(sk_active)}    (vorne)")
    warn(f"  Standby SK: sha256={fingerprint(sk_standby)}  (hinten)")

    info("\n  Phase 3: Active crasht, Standby promotet sich zum neuen Active")
    bad("  Standby uebernimmt mit aelterem SK-Stand!")

    sk_new_active = sk_standby
    msg_after_failover = b"NEW ACTIVE: process payment $5000"
    sig_after_failover, _ = scheme.sign(sk_new_active, msg_after_failover)
    idx_after = int.from_bytes(sig_after_failover[:4], "big")
    info(f"  Neuer Active signiert mit Index {idx_after}")
    bad(f"  Index {idx_after} wurde aber bereits vom alten Active verwendet")
    bad("  fuer 'async-payment-1' / 'async-payment-2' - Reuse!")

    section("Quervergleich mit anderen Verfahren")
    explain("""
        ML-DSA und SLH-DSA waeren in beiden Szenarien voellig
        unproblematisch. Beide Knoten koennen denselben SK halten und
        unabhaengig signieren - der SK ist keine knappe Ressource.
        Genau das macht 'stateless' zu einem Operations-Vorteil, der
        oft den Mehraufwand bei Signaturgroesse rechtfertigt.
    """)

    takeaway("""
        Stateful-Signaturen sind mit Standard-HA-Mustern nicht
        kompatibel. Die einzigen sicheren Architekturen: (1) ein
        einziger sequentieller Signierer (kein HA), (2) eine
        Signing-API, die ueber globalen Lock serialisiert (= teurer
        Single-Writer), oder (3) jeden Knoten mit EIGENEM Schluessel
        ausstatten und mehrere Public Keys an Verifier verteilen.
        Empfehlung von NIST SP 800-208: stateful nur dort einsetzen,
        wo der Anwendungsfall es zwingend erfordert.
    """)


if __name__ == "__main__":
    main()