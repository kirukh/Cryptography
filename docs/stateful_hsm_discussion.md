# Stateful Hash-Based Signatures in der Praxis: Standardisierung und HSM

Dieses Dokument ergaenzt die Demos in `src/stateful_demo/` um den
industriellen Kontext: Wie geht die Standardisierung mit der
Statefulness-Problematik um, und was bedeutet das fuer praktische
Implementierungen?

## NIST SP 800-208 und das Backup-Paradoxon

NIST hat 2020 die Special Publication 800-208 veroeffentlicht, die
XMSS und LMS (sowie XMSSMT/HSS) als zugelassene Verfahren fuer
US-Behoerden definiert. Drei Anforderungen praegen die Praxis:

1. **Nur Hardware-Implementierungen sind validierbar.** Software-XMSS
   wie in dieser Arbeit ist ausserhalb der NIST-Compliance.
2. **FIPS 140-3 Level 3 oder hoeher** verlangt physische
   Tamper-Evidence — also "echte" HSMs (Thales Luna, Utimaco,
   AWS CloudHSM).
3. **Kein Export des Private Keys.** Der Schluessel darf das Modul
   nie verlassen.

Punkt 3 ist die eigentliche Pointe: er macht klassisches Backup
unmoeglich. Wenn ein HSM ausfaellt, ist der Schluessel verloren —
und mit ihm jede Signatur-Faehigkeit fuer den zugehoerigen Public
Key. Bei Code-Signing-Schluesseln, die in ausgelieferte Geraete
eingebrannt sind, ist Re-Issuance teilweise unmoeglich.

NIST hat 2024 angekuendigt, SP 800-208 zu ueberarbeiten, um doch
eine Form von Schluesselexport zu ermoeglichen — getrieben durch
genau dieses Backup-Paradoxon.

## Wie HSM-Hersteller damit umgehen

Beispiel Thales (Luna 7.15.0, 2024): LMS/HSS-Support direkt im HSM,
Index als Teil des Schluessels in tamper-resistant Storage. Aus dem
Whitepaper "Quantum-Resistant Code Signing":

> "private keys cannot be cloned to other HSMs to establish high
> availability and redundancy."

Stattdessen: Multi-Tree-Architektur. Jeder HSM bekommt einen
disjunkten Sub-Tree des XMSSMT-Baums, verwaltet seinen eigenen
Index in seinem Sub-Tree. Public Key ist die Wurzel des Gesamtbaums
— fuer Verifier transparent. Damit ist Hochverfuegbarkeit moeglich,
ohne dass HSMs den State teilen muessen.

Genau dieselbe Logik laeuft hinter den Demos in
`src/stateful_demo/`: sobald mehrere Knoten *denselben* SK halten,
kollabiert die Stateful-Garantie. Die Industrie-Antwort ist nicht
"Synchronisation loesen", sondern "den State so partitionieren,
dass keine geteilt werden muss".

## Empfehlungs-Matrix

| Anwendungsfall              | Empfehlung               |
|-----------------------------|--------------------------|
| TLS, allgemeines Signieren  | ML-DSA                   |
| Code-Signing (CNSA 2.0)     | LMS/XMSSMT in HSM        |
| Firmware-Signing (frei)     | SLH-DSA oder XMSS in HSM |
| Audit-Logs / Compliance     | ML-DSA oder SLH-DSA      |

## Fazit

Die Demos zeigen: die Statefulness-Probleme von XMSS folgen direkt
aus alltaeglichen IT-Praktiken (Backup, Failover, Replikation). Die
Industrie-Antwort ist zweigeteilt: dort wo XMSS/LMS regulatorisch
verlangt werden (CNSA 2.0 Code-Signing), kommen teure
Hardware-HSMs mit nicht-exportierbaren Schluesseln zum Einsatz. In
allen anderen Faellen wird auf stateless Verfahren ausgewichen —
ML-DSA fuer Performance, SLH-DSA fuer konservative
Sicherheitsannahmen.

XMSS bleibt damit ein Nischenverfahren. Die tragenden Saeulen der
PQ-Migration sind ML-DSA und SLH-DSA.

## Quellen

- NIST SP 800-208 (2020) — Recommendation for Stateful Hash-Based
  Signature Schemes
- NIST PQC Forum — Diskussion zur SP 800-208 Revision (2024)
- NSA CNSA 2.0 (September 2022)
- RFC 8391 (XMSS)
- Thales Trusted Cyber Technologies — Quantum-Resistant Code
  Signing Whitepaper (2024)
- Buchmann, Dahmen, Huelsing — XMSS, PQCrypto 2011
