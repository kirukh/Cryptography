"""
Demo 3 - Die Backup-Falle.

Lehrziel: Demo 2 hat das Reuse-Problem abstrakt gezeigt. Jetzt betten
wir es in ein REALISTISCHES Operations-Szenario ein.

Szenario:
    Eine Anwendung schreibt Audit-Log-Eintraege und signiert sie mit
    XMSS. Der Sysadmin macht naechtlich Backup. Eines Tages crashed
    der Server, das Backup wird zurueckgespielt. Was passiert mit
    dem Index?

Aufruf:
    python -m src.stateful_demo.demo03_backup_pitfall
"""
from src.algorithms import XMSSScheme
from src.stateful_demo._console import (
    banner, section, info, good, bad, warn, explain,
    fingerprint, takeaway,
)


def main():
    banner("Demo 3: Die Backup-Falle (realistisches Szenario)")

    explain("""
        Wir simulieren eine Audit-Log-Anwendung, die jeden Eintrag mit
        XMSS signiert. Standard-Operations-Praktiken (Backup, Restore)
        fuehren ohne entsprechende Vorkehrungen direkt in die
        Index-Kollision.
    """)

    scheme = XMSSScheme("XMSS-SHA2_10_256")
    kp = scheme.keygen()
    pk = kp.public_key

    # liboqs zaehlt den initialen Index als 'allokiert' mit; der Wert
    # ist also 1023 statt der theoretischen 1024 bei 2^10. Wir merken
    # uns den initialen Pool-Wert statt eine Konstante zu nutzen, damit
    # die Demo robust gegen diese Implementierungs-Konvention bleibt.
    INITIAL_POOL = scheme.remaining_signatures(kp.secret_key)

    # Audit log mit (Nachricht, Sig, Index).
    audit_log: list[tuple[bytes, bytes, int]] = []

    def log_entry(msg: bytes, sig: bytes) -> None:
        idx = int.from_bytes(sig[:4], "big")
        audit_log.append((msg, sig, idx))
        good(f"  Log-Eintrag #{len(audit_log)} (Index {idx}): {msg.decode()}")

    # ---- Tag 1 ----
    section("Tag 1, 09:00 Uhr - normaler Betrieb")
    sk = kp.secret_key
    msgs_day1 = [
        b"User alice logged in",
        b"File /etc/passwd accessed",
        b"User alice logged out",
    ]
    for msg in msgs_day1:
        sig, sk = scheme.sign(sk, msg)
        log_entry(msg, sig)

    section("Tag 1, 23:00 Uhr - naechtliches Backup")
    sk_backup = sk   # <-- Snapshot wird in Backup-System geschrieben
    info(f"SK-Backup gespeichert (sha256={fingerprint(sk_backup)})")
    info(f"Naechster freier Index laut Backup: "
         f"{INITIAL_POOL - scheme.remaining_signatures(sk_backup)}")

    # ---- Tag 2 ----
    section("Tag 2, 10:00 Uhr - weiterer Betrieb")
    msgs_day2 = [
        b"User bob logged in",
        b"DB query: SELECT * FROM users",
        b"DB query: UPDATE config",
        b"User bob logged out",
    ]
    for msg in msgs_day2:
        sig, sk = scheme.sign(sk, msg)
        log_entry(msg, sig)

    section("Tag 2, 14:00 Uhr - Server-Crash und Restore")
    explain("""
        Der Server-Storage hat ein Problem - Disk-Failure oder
        defektes Filesystem. Der Admin spielt das Backup von gestern
        Nacht zurueck. Aus Sicht des Backups ist alles in Ordnung:
        die Datei ist konsistent, das Filesystem ist sauber.

        ABER: der Index steht jetzt wieder auf dem Wert von gestern
        Nacht. Alle 4 Signaturen vom Tag 2 haben Indizes, die das
        System fuer 'frei' haelt.
    """)

    sk_after_restore = sk_backup
    next_free_idx = INITIAL_POOL - scheme.remaining_signatures(sk_after_restore)
    warn(f"Naechster 'freier' Index nach Restore: {next_free_idx}")
    if 0 <= next_free_idx < len(audit_log):
        warn("Aber dieser Index wurde heute morgen schon benutzt fuer:")
        info(f"  '{audit_log[next_free_idx][0].decode()}' "
             f"(Index {audit_log[next_free_idx][2]})")

    section("Tag 2, 14:30 Uhr - neue Signaturen nach dem Restore")
    sk = sk_after_restore
    msgs_after_restore = [
        b"AFTER RESTORE: User attacker logged in",
        b"AFTER RESTORE: File /etc/shadow accessed",
    ]
    new_entries = []
    for msg in msgs_after_restore:
        sig, sk = scheme.sign(sk, msg)
        idx = int.from_bytes(sig[:4], "big")
        new_entries.append((msg, sig, idx))
        bad(f"  NEU signiert: '{msg.decode()}' mit Index {idx}")

    section("Audit-Log-Forensik: was sagt der Verifier?")
    explain("""
        Wenn wir jetzt die Logs gegenpruefen, sehen wir das Drama:
        Fuer manche Indizes existieren ZWEI verschiedene Eintraege,
        beide kryptographisch gueltig.
    """)

    for new_msg, new_sig, new_idx in new_entries:
        for old_msg, old_sig, old_idx in audit_log:
            if old_idx == new_idx:
                bad(f"\n  KOLLISION an Index {new_idx}:")
                info(f"    Alt: '{old_msg.decode()}'")
                info(f"         verify={scheme.verify(pk, old_msg, old_sig)}")
                info(f"    Neu: '{new_msg.decode()}'")
                info(f"         verify={scheme.verify(pk, new_msg, new_sig)}")
                bad("    -> Aus PK-Sicht sind BEIDE Eintraege legitim signiert.")

    section("Audit-Trail vollstaendig kompromittiert")
    info(f"Anzahl Log-Eintraege total:   {len(audit_log) + len(new_entries)}")
    info(f"Anzahl kollidierende Indizes: {len(new_entries)}")
    bad("Die Audit-Eigenschaft 'manipulationssicher' ist verletzt:")
    info("  - Ein Auditor kann nicht mehr zwischen 'echt' und 'untergeschoben'")
    info("    unterscheiden, ohne Out-of-Band-Information zu konsultieren.")

    takeaway("""
        Klassische Backup-Strategien (auch saubere, taegliche Backups
        einer korrekt arbeitenden Anwendung!) sind mit naiven
        XMSS-Setups inkompatibel. Loesungsansaetze: (a) niemals den SK
        ins Backup nehmen, sondern bei Verlust einen neuen Schluessel
        ausstellen; (b) statefulness an spezialisierte Hardware
        delegieren (HSM); oder (c) auf stateless-Verfahren wie ML-DSA /
        SLH-DSA wechseln, wo dieses Problem ueberhaupt nicht existiert.
    """)


if __name__ == "__main__":
    main()
