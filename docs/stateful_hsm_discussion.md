# HSM- und Industrie-Diskussion zu Stateful Hash-Based Signatures

Dieses Dokument ergaenzt die vier praktischen Demos um den industriellen
Kontext: Wie geht die Industrie mit der Statefulness-Problematik um? Was
sagen Standardisierungsgremien? Und warum ist die Antwort fast immer
"in einem HSM" — und gleichzeitig fast immer "vermeide es, wenn moeglich"?

## 1. Die regulatorische Lage

### NIST SP 800-208 (2020)

NIST hat 2020 die Special Publication 800-208 veroeffentlicht, die XMSS
und LMS (sowie ihre Multi-Tree-Varianten XMSSMT und HSS) als zugelassene
Signaturverfahren fuer US-Behoerden profiliert. Die zentrale Aussage zur
Implementierung ist drastisch:

> "Implementations of the key generation and signature algorithms in this
> document shall only be validated for use within hardware cryptographic
> modules. The cryptographic modules shall be validated to provide
> FIPS 140-2 or FIPS 140-3 Level 3 or higher physical security ... The
> cryptographic module shall not allow for the export of private keying
> material."

Drei harte Anforderungen, die unmittelbare Konsequenzen haben:

1. **Software-Implementierungen sind NICHT zugelassen.** Wer XMSS in einer
   Pure-Software-Loesung einsetzt (wie wir es in den Demos tun), ist
   ausserhalb der NIST-Compliance.
2. **FIPS-140-3 Level 3** verlangt physische Tamper-Evidence sowie
   identitaetsbasierte Authentifizierung — also Hardware vom Typ "richtige"
   HSMs (Thales Luna, Utimaco, AWS CloudHSM, ...).
3. **Kein Export des Private Keys** macht klassisches Backup unmoeglich.

### Das Backup-Paradoxon der Standardisierung

Genau hier zeigt sich, warum SP 800-208 so schwer umzusetzen ist: Backup
ist eine grundlegende IT-Operations-Praxis, aber das Standard verbietet
sie effektiv. Wenn ein HSM ausfaellt, ist der Schluessel verloren und
muss durch Re-Issuance ersetzt werden — was bei Code-Signing-Schluesseln,
die in Geraete eingebrannt sind, oft nicht moeglich ist.

### NIST plant eine Revision (Stand 2024/25)

NIST hat 2024 angekuendigt, SP 800-208 zu ueberarbeiten, um doch eine
Form von Schluesselexport zu ermoeglichen — getrieben durch Industrie-
Feedback, dass die strikten Regeln den praktischen Einsatz blockieren.
Die Diskussionen auf dem PQC-Forum zeigen: ein Vorschlag ist, den
Schluessel in einen stateless Teil (Seeds, Parameter) und einen stateful
Teil (nur den Index) zu trennen, sodass nur der grosse, zeitlich stabile
Anteil normal gebackupt werden kann.

### CNSA 2.0 (NSA, September 2022)

Die NSA hat in der Commercial National Security Algorithm Suite 2.0 eine
Roadmap fuer den PQC-Uebergang in National-Security-Systemen verbindlich
gemacht. Bemerkenswert: CNSA 2.0 erlaubt KEIN stateless hash-basiertes
Verfahren (also kein SLH-DSA) als Alternative zu LMS/XMSS — fuer
Firmware-Signing und Code-Signing wird ausdruecklich auf stateful HBS
gesetzt. Begruendung: kleine Signaturen, schnelle Verifikation, sehr
konservative Sicherheitsannahmen.

Damit sind grosse Code-Signing-Projekte unter NSA-Kompetenz an die
Statefulness-Problematik gebunden, ob sie wollen oder nicht.

## 2. Wie loesen HSM-Hersteller das Problem?

### Thales Luna & TCT

Thales hat ab Luna 7.15.0 (2024) LMS/HSS-Support direkt in den HSMs.
Schluesselgenerierung und Signing laufen vollstaendig im HSM, der Index
wird als Teil des Schluessels in tamper-resistant Storage verwaltet.
Thales' eigene Empfehlung im Whitepaper "Quantum-Resistant Code Signing":

> "private keys cannot be cloned to other HSMs to establish high
> availability and redundancy."

Stattdessen empfiehlt Thales die Lebenszyklus-Architektur:

- Eine Familie von HSMs uebernimmt jeweils einen Sub-Tree des XMSSMT-Baums
- Jeder HSM verwaltet seinen eigenen Index in seinem Sub-Tree
- Public Key ist die Wurzel des Gesamtbaums — fuer Verifier ist das
  transparent

Das ist ein Beispiel fuer die "Multi-Tree-als-Workaround"-Strategie:
Jeder HSM bekommt sein eigenes Sub-Universum von Indizes und kann nicht
mit anderen HSMs kollidieren — solange das Sub-Tree-Mapping korrekt ist.

### AWS, Google, Cloudflare

Cloudflare hat in eigenen Blog-Posts dokumentiert, dass sie LMS fuer
Firmware-Signing verwenden, aber den Grossteil ihrer PQ-Migration
auf ML-DSA stuetzen, wo es geht. Begruendung: die Stateful-Hygiene
in einer global verteilten Infrastruktur ist zu fragil.

AWS bietet seit 2023 LMS-Support in CloudHSM und KMS — aber wieder mit
expliziten Warnhinweisen, dass Cloning, Snapshotting und Cross-Region-
Replication NICHT verwendet werden duerfen.

### wolfSSL

Die Bibliothek wolfSSL ist insofern bemerkenswert, als sie LMS und XMSS
in Software unterstuetzt, aber SP-800-208-Compliance explizit nicht
beansprucht. Sie bieten einen Build-Flag `--enable-lms=verify-only`
fuer Verifier-Geraete, sodass Embedded-Geraete die Signaturen pruefen
koennen, ohne ueber Sign-/Keygen-Infrastruktur verfuegen zu muessen —
das ist die typische Aufteilung "ein vertrauenswuerdiger Signer pro
Produkt-Familie, viele Verifier in den Geraeten".

## 3. Wann ist Stateful trotzdem die richtige Wahl?

Trotz aller Probleme ist XMSS/LMS nicht obsolet. Sinnvolle
Anwendungsfaelle:

### 3.1 Firmware- und Boot-Signing

Wenn ein eingebettetes Geraet einen Bootloader verifizieren soll, kommt
es auf:
- Sehr kleine Verifier-Implementierung (wenige KB Code) — passt fuer XMSS,
  passt fuer SLH-DSA.
- Schnelle Verifikation — XMSS hat die Nase vorn.
- Konservative Sicherheitsbasis — nur Hash-Funktion, keine Annahmen ueber
  Gitter — passt fuer XMSS und SLH-DSA gleichermassen.
- Wenige Signaturen pro Lebensdauer — passt fuer XMSS (1024 oder 2^20
  Firmware-Updates reichen weit ueber Geraete-Lebensdauer hinaus).

In diesem Profil punktet XMSS mit deutlich kleinerer Signatur als SLH-DSA
(2.5 KB vs 17 KB fuer 128-Bit-Sicherheit), was bei knappem Flash relevant
ist.

### 3.2 Sub-CA-Schluessel mit definiertem Volumen

Wenn klar ist, dass ein bestimmter Schluessel nur fuer N Signaturen
verwendet wird (z.B. eine Zeitstempel-Autoritaet mit deterministischem
Pensum), ist die Index-Endlichkeit kein Bug, sondern ein Feature —
"diese Stelle hat hoechstens N Signaturen ausgestellt" ist eine
nuetzliche Eigenschaft fuer Audits.

### 3.3 Single-Signer-Architekturen

Wenn die Anwendung sowieso nur einen einzigen Signing-Knoten hat (z.B. ein
zentraler Build-Server, der nicht horizontal skaliert), faellt die
HA-Problematik aus. Backup loest man durch eine **vorausschauende**
Strategie: bei der Schluesselgenerierung wird der Schluessel in mehrere
disjunkte Index-Bereiche aufgeteilt, die als separate Schluessel behandelt
werden. Faellt ein Bereich aus, wird er fallengelassen, der naechste
ueber.

## 4. Empfehlungs-Matrix

| Anwendungsfall              | Empfehlung               | Begruendung |
|-----------------------------|--------------------------|-------------|
| TLS, allgemeines Signieren  | **ML-DSA**               | beste Performance bei akzeptablen Groessen |
| Code-Signing (CNSA 2.0)     | LMS/XMSSMT in HSM        | regulatorisch verlangt |
| Firmware-Signing (frei)     | **SLH-DSA** oder XMSS    | beide gut, SLH-DSA betriebssicherer |
| Audit-Logs / Compliance     | **ML-DSA** oder SLH-DSA  | Stateful waere fragile |
| Zeitstempel-Autoritaet      | XMSSMT in HSM            | definiertes Volumen, kleine Sigs |
| Embedded-Verifikation only  | XMSS oder SLH-DSA        | beide haben kleine Verifier |

## 5. Fazit fuer die Arbeit

Die Demos in `src/stateful_demo/` zeigen, dass die Statefulness-Probleme
nicht hypothetisch sind, sondern direkt aus alltaeglichen IT-Praktiken
folgen — Backup, Failover, Replikation. Die Industrie-Antwort ist
zweigeteilt:

1. Fuer den Pflicht-Anwendungsfall (CNSA 2.0 Code-Signing): teure
   FIPS-140-3-Level-3-HSMs mit nicht-exportierbaren Schluesseln und
   Multi-Tree-Verteilung.
2. Fuer alle anderen Faelle: stateless Verfahren (ML-DSA fuer
   Performance, SLH-DSA fuer konservative Sicherheit).

Diese Bifurkation ist auch ein Argument dafuer, dass XMSS auf lange
Sicht ein **Nischenverfahren** bleibt, waehrend ML-DSA und SLH-DSA die
tragenden Saeulen der PQ-Migration werden.

## Quellen

- NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes (2020)
- NIST PQC Forum, "Update on SP 800-208" Diskussion (2024)
- NSA CNSA 2.0 (September 2022)
- RFC 8391 (XMSS), RFC 8554 (LMS)
- Thales Trusted Cyber Technologies, "Quantum-Resistant Code Signing
  Secured by Hardware Security Modules" Whitepaper (2024)
- wolfSSL, "Special Rules for LMS and XMSS" (2024)
- Buchmann, Dahmen, Huelsing: "XMSS - A Practical Forward Secure
  Signature Scheme Based on Minimal Security Assumptions", PQCrypto 2011
