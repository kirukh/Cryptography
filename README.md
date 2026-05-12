# pq-bench

Vergleich der Post-Quantum-Signaturverfahren **ML-DSA**, **SLH-DSA** und
**XMSS** mit besonderem Fokus auf die Statefulness-Problematik von XMSS.

Projektarbeit im Umfang von ~60 Stunden. Diese README enthält neben
einer Einführung auch die vollständige Schritt-für-Schritt-Anleitung
zum Einrichten und Ausführen in WSL2 (Windows 11) — geeignet als
Referenz für die Reproduktion der Messungen und Demos in der
Ausarbeitung.

---

## Inhaltsverzeichnis

1. [Kurzüberblick](#1-kurzüberblick)
2. [Projektstruktur](#2-projektstruktur)
3. [Setup in WSL2 (komplette Anleitung)](#3-setup-in-wsl2-komplette-anleitung)
4. [Arbeiten im Projekt](#4-arbeiten-im-projekt)
5. [Was die einzelnen Programme zeigen](#5-was-die-einzelnen-programme-zeigen)
6. [Methodische Notizen für die Ausarbeitung](#6-methodische-notizen-für-die-ausarbeitung)
7. [Troubleshooting](#7-troubleshooting)
8. [Lizenzen und Quellen](#8-lizenzen-und-quellen)

---

## 1. Kurzüberblick

### Forschungsfrage

Welche der drei NIST-relevanten Post-Quantum-Signaturverfahren ist
*praktisch einsetzbar* — und welche systemischen Probleme entstehen
jeweils? Insbesondere: warum ist XMSS trotz konservativer
Sicherheitsannahmen kein universeller Ersatz für RSA/ECDSA?

### Vergleichsmatrix

| | ML-DSA (FIPS 204) | SLH-DSA (FIPS 205) | XMSS (RFC 8391) |
|---|---|---|---|
| Mathematische Basis | Module-LWE (Gitter) | Hash-Funktionen | Hash-Funktionen |
| Stateful? | nein | nein | **ja** |
| Sicherheitsannahme | neuer (LWE) | konservativ | konservativ |
| Signaturen pro Schlüssel | unbegrenzt | unbegrenzt | endlich (2^h) |
| Rolle in der Auswahl | Allzweck-Standard | konservative Hash-Alternative | Spezial-Verfahren (Code-Signing) |

### Hauptbefund

> **XMSS bricht nicht durch kryptanalytische Schwäche, sondern durch
> die Verletzung seines Operations-Modells.** Genau dieses Modell — ein
> einziger sequentieller Signierer mit perfekter State-Persistenz — ist
> mit den Standard-Praktiken realer IT-Systeme (Backup, HA-Failover,
> Replikation) nicht vereinbar.

---

## 2. Projektstruktur

```
pq-bench/
├── src/
│   ├── algorithms/              # Algorithmus-Wrapper
│   │   ├── base.py              #   Abstraktes Interface
│   │   ├── mldsa_wrapper.py     #   ML-DSA-65
│   │   ├── sphincs_wrapper.py   #   SLH-DSA-SHA2-128f
│   │   └── xmss_wrapper.py      #   XMSS-SHA2_10_256
│   ├── benchmark/               # Mess-Logik
│   │   ├── metrics.py           #   Mess-Mechanik
│   │   └── runner.py            #   Orchestrierung + CSV-Output
│   ├── stateful_demo/           # XMSS-Statefulness-Demos
│   │   ├── demo02_reuse_attack.py
│   │   ├── demo03_backup_pitfall.py
│   │   ├── demo04_multinode_failover.py
│   │   └── run_all.py
│   ├── run_benchmark.py         # Entry-Point Benchmark
│   └── smoke_test.py            # Roundtrip-Check
├── tests/                       # 79 Tests, alle grün
│   ├── conftest.py
│   ├── test_wrappers_common.py
│   ├── test_stateless_property.py
│   └── test_xmss_stateful.py
├── docs/
│   └── stateful_hsm_discussion.md
├── results/                     # CSV-Output
├── pytest.ini
├── requirements.txt
├── setup_liboqs.sh              # liboqs-Build-Script
└── README.md
```

---

## 3. Setup in WSL2 (komplette Anleitung)

Diese Anleitung ist auf **Windows 11 mit WSL2 Ubuntu 22.04** ausgelegt.
Auf einem nativen Ubuntu-System gelten die Schritte ab 3.2 analog.

### 3.1 WSL2 + Ubuntu installieren (einmalig)

Falls noch nicht vorhanden, in einer Windows-PowerShell **als
Administrator**:

```powershell
wsl --install -d Ubuntu-22.04
```

Nach Neustart einmal Ubuntu-User anlegen, dann landest du in der
Ubuntu-Shell.

### 3.2 System-Pakete installieren

In der Ubuntu-Shell:

```bash
sudo apt update
sudo apt install -y build-essential cmake git ninja-build \
    libssl-dev python3 python3-pip python3-venv python3-dev pkg-config \
    astyle gcc libtool unzip wget
```

Diese Pakete brauchst du, weil liboqs aus dem Quellcode gebaut werden
muss — eine fertige Distribution mit aktiviertem XMSS gibt es nicht.

### 3.3 Projekt nach WSL holen

```bash
mkdir -p ~/projects
cd ~/projects
# Variante a: aus Git-Repo
git clone <deine-repo-url> pq-bench
cd pq-bench

# Variante b: aus einem Tarball, der unter /mnt/c/... liegt
# cp /mnt/c/Users/<DEIN-USER>/Downloads/pq-bench.tar.gz ~/projects/
# tar xzf pq-bench.tar.gz
# cd pq-bench
```

### 3.4 Python-Venv anlegen und Pakete installieren

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.5 liboqs mit XMSS-Support bauen

Das ist der kritische Schritt. Standardmäßig deaktiviert liboqs den
XMSS-Support aus Sicherheitsgründen (Stateful-Gefahr). Unser Script
aktiviert ihn bewusst:

```bash
bash setup_liboqs.sh
```

Das dauert **5–10 Minuten** je nach Hardware. Das Script:

- Klont liboqs Tag **0.15.0** nach `vendor/liboqs/`
- Klont liboqs-python Tag **0.14.0** nach `vendor/liboqs-python/`
- Baut liboqs mit den Flags `OQS_ENABLE_SIG_STFL_XMSS=ON` und
  `OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON`
- Installiert die Bibliothek nach `vendor/install/`
- Installiert liboqs-python in das aktive venv

> **Versions-Hinweis:** liboqs 0.15.0 ↔ liboqs-python 0.14.0 ist die
> aktuelle Kombination. Beim Import erscheint eine `UserWarning` über
> die Versions-Differenz — das ist funktional irrelevant.

### 3.6 LD_LIBRARY_PATH setzen

Damit Python die liboqs-Bibliothek zur Laufzeit findet:

```bash
export LD_LIBRARY_PATH="$(pwd)/vendor/install/lib:${LD_LIBRARY_PATH:-}"
```

**Dauerhafte Lösung** (empfohlen): hänge die Zeile an deine `~/.bashrc`
an, mit dem absoluten Pfad:

```bash
echo "export LD_LIBRARY_PATH=\"$HOME/projects/pq-bench/vendor/install/lib:\${LD_LIBRARY_PATH:-}\"" >> ~/.bashrc
```

Bei neuer Shell danach automatisch gesetzt.

### 3.7 Setup verifizieren

```bash
python -c "import oqs; print(oqs.oqs_version())"
```

Erwartete Ausgabe:

```
liboqs-python faulthandler is disabled
...UserWarning: liboqs version (major, minor) 0.15.0 differs from liboqs-python version 0.14.0
0.15.0
```

Wenn die Versions-Zeile (`0.15.0`) am Ende steht, ist alles korrekt
verdrahtet.

### 3.8 Smoke-Test

```bash
python -m src.smoke_test
```

Erwartete Ausgabe: für alle drei Algorithmen "OK" am Ende der
Zusammenfassung. Wenn das klappt, ist das Setup komplett.

---

## 4. Arbeiten im Projekt

Jede neue Shell-Session braucht zwei Dinge: aktiviertes venv und
gesetzten Library-Pfad. Bei dauerhafter `~/.bashrc`-Konfiguration
entfällt der zweite Schritt.

```bash
cd ~/projects/pq-bench
source .venv/bin/activate
# falls nicht in ~/.bashrc:
export LD_LIBRARY_PATH="$(pwd)/vendor/install/lib:${LD_LIBRARY_PATH:-}"
```

### 4.1 Tests ausführen

```bash
pytest
```

Erwartet: `79 passed`. Laufzeit ~15–60 Sekunden, je nach Hardware. Die
XMSS-keygen-Aufrufe sind der Flaschenhals.

Mit Live-Output während des Laufs:

```bash
pytest -v -s
```

### 4.2 Benchmark ausführen

```bash
python -m src.run_benchmark
```

Schreibt drei CSV-Dateien nach `results/`:
- `results_summary.csv` — eine Zeile pro (Algorithmus, Operation)
- `results_raw.csv` — eine Zeile pro Einzelmessung
- `results_sizes.csv` — PK/SK/Signatur-Größen

Zusätzlich wird eine Zusammenfassungs-Tabelle auf der Konsole gedruckt
— **diese Tabelle ist die Vorlage für die Performance-Tabelle in der
Ausarbeitung**.

Laufzeit: ~1–3 Minuten.

### 4.3 Statefulness-Demos ausführen

Einzeln:

```bash
python -m src.stateful_demo.demo02_reuse_attack
python -m src.stateful_demo.demo03_backup_pitfall
python -m src.stateful_demo.demo04_multinode_failover
```

Alle drei am Stück:

```bash
python -m src.stateful_demo.run_all
```

Diese Programme sind didaktisch gestaltet (Banner, Sections, farbige
Hinweise). Sie eignen sich direkt als Live-Demo in der Präsentation und
als Screenshot-Quelle für die Ausarbeitung.

---

## 5. Was die einzelnen Programme zeigen

### 5.1 Smoke-Test (`src/smoke_test.py`)

Roundtrip-Check: keygen → sign → verify, plus Negativtest. Für jeden
Algorithmus werden Größen ausgegeben und die Stateful-Eigenschaft von
XMSS demonstriert (Veränderung des SK, verbleibende Signaturen).

**Screenshot-Idee:** der "Zusammenfassung"-Block am Ende mit drei mal
"OK" — zeigt im Doku-Kapitel "Aufbau" auf einen Blick, dass die
Umgebung lauffähig ist.

### 5.2 Benchmark (`src/run_benchmark.py`)

Misst keygen, sign, verify mit folgenden Defaults:
- keygen: 20 Iterationen, 2 Warmup
- sign: 100 Iterationen, 5 Warmup
- verify: 100 Iterationen, 5 Warmup

Mess-Methodik im Detail:
- `time.perf_counter_ns()` für hochauflösende monotonische Zeitstempel
- Warmup-Iterationen werden verworfen (kalter Cache, Branch-Predictor)
- Median als robuste Hauptmetrik (gegen GC-Pausen), Mean und Stdev als
  Nebenmetriken

**Screenshot-Idee:** die Zusammenfassungs-Tabellen aus dem Runner —
ergeben die "Performance-Tabelle" und "Größen-Tabelle" in der
Ausarbeitung.

### 5.3 Demo 2: Reuse-Attack (`demo02_reuse_attack.py`)

Zeigt das Grundproblem abstrakt:
- Schlüssel erzeugen, Snapshot speichern
- Drei legitime Signaturen
- Snapshot wiederherstellen ("Backup-Restore")
- Erneut signieren → zwei Signaturen mit **identischem Index 0**, beide
  unter demselben Public Key gültig

**Screenshot-Idee:** die Stelle "BEIDE Signaturen verwenden denselben
Index 0" — das ist der visuell stärkste Beleg des Reuse-Problems.

### 5.4 Demo 3: Backup-Falle (`demo03_backup_pitfall.py`)

Realistisches Operations-Szenario:
- Audit-Log-Anwendung über zwei "Tage"
- Nächtliches Backup
- Server-Crash und Restore
- Folge: kollidierende Indizes im Audit-Log mit unterschiedlichen
  Nachrichten, alle kryptographisch gültig

**Screenshot-Idee:** die "KOLLISION an Index N"-Stelle. Das ist die
emotional packendste Demo, weil sie zeigt: kein Programmierfehler, kein
fahrlässiger Admin — Standard-Operations-Praxis führt direkt in den
Reuse.

### 5.5 Demo 4: Multi-Node-Failover (`demo04_multinode_failover.py`)

Zwei Szenarien:
- Active-Active mit Shared Storage (Race Condition)
- Active-Standby mit asynchroner Replikation (Replikations-Lag bei
  Failover)

Zeigt: Statefulness ist mit klassischen HA-Patterns strukturell
inkompatibel.

### 5.6 Tests (`tests/`)

79 Tests in vier Modulen:
- `test_wrappers_common.py` — parametrisiert über alle drei
  Algorithmen, prüft Roundtrip, Größen, Negative Cases
- `test_stateless_property.py` — explizite Stateless-Garantie für
  ML-DSA und SLH-DSA
- `test_xmss_stateful.py` — **Kernstück**: Index-Progression,
  monotoner Counter, Reuse-Detektion als testbarer Beleg

Besonderheit: die Tests in `TestStateReuse` sind keine Bug-Tests,
sondern **Belege** für das spezifizierte Verhalten. Falls liboqs in
einer späteren Version eine Reuse-Detektion einbaut, würden diese Tests
fehlschlagen — was Anlass wäre, die Diskussion in der Arbeit zu
aktualisieren.

**Screenshot-Idee:** der pytest-Output mit `79 passed` — belegt
visuell die Test-Coverage.

---

## 6. Methodische Notizen für die Ausarbeitung

### 6.1 Reproduzierbarkeit

Alle Messungen sind reproduzierbar:
- Pinned Versionen: liboqs 0.15.0, liboqs-python 0.14.0
- Festgelegte Iterationen pro Operation (siehe `runner.py`)
- Median statt Mean → robust gegen Ausreißer
- Warmup eliminiert Cold-Cache-Effekte

In der Ausarbeitung erwähnen:
- Hardware-Spezifikation (CPU, RAM)
- Betriebssystem (WSL2 / Ubuntu 22.04)
- liboqs-Version

### 6.2 liboqs-Konventionen, die in der Arbeit erwähnt werden sollten

- liboqs hat **stateful Sigs standardmäßig deaktiviert**. Die
  HAZARDOUS-Flags müssen explizit gesetzt werden — eine
  Design-Entscheidung, die selbst Teil der Argumentation ist
- liboqs reportet `remaining_signatures` für XMSS-SHA2_10_256 direkt
  nach keygen als **1023** statt 1024. Der initiale Index wird intern
  als "allokiert" gezählt. Funktional ohne Konsequenz, aber in der
  Arbeit erwähnen, um Off-by-One-Diskussionen vorzubeugen

### 6.3 Was die Performance-Zahlen *nicht* zeigen

- Memory-Footprint wird nicht aussagekräftig gemessen (tracemalloc
  sieht nur Python-Heap, nicht C-Heap). In der Ausarbeitung
  entsprechend einordnen
- Wir messen nicht mit verschiedenen Nachrichtengrößen — bei
  Signaturverfahren in der Regel irrelevant (intern wird gehasht), aber
  ein möglicher Diskussionspunkt
- Multi-Threading-Verhalten und Skalierung sind nicht untersucht

### 6.4 Begründung der Parameter-Sets

Eine Variante pro Algorithmus reicht für den qualitativen Vergleich:
- **ML-DSA-65** als Mittelweg (NIST Level 3)
- **SLH-DSA-SHA2-128f** als gängiger Vergleichspunkt in der Literatur
- **XMSS-SHA2_10_256** als kleinstes Set — keygen sonst minutenlang

### 6.5 Demo-Skripte als ausführbarer Belegtext

Die drei Statefulness-Demos sind nicht "Spielereien", sondern bilden
den argumentativen Kern: jede Demo entspricht einer These der
Ausarbeitung.

| Demo | These |
|---|---|
| Demo 2 | Reuse ist unmittelbare Folge eines SK-Snapshots |
| Demo 3 | Standard-Backup-Praxis erzeugt Reuse |
| Demo 4 | Klassische HA-Patterns sind inkompatibel mit Stateful-Sigs |

---

## 7. Troubleshooting

### `ModuleNotFoundError: No module named 'oqs'`

Das venv ist nicht aktiv oder `pip install` wurde übersprungen.
Lösung: `source .venv/bin/activate` und ggf. `pip install -r
requirements.txt`.

### `oqs.MechanismNotSupportedError: 'XMSS-SHA2_10_256' is not a supported mechanism`

liboqs wurde ohne XMSS-Support gebaut. Lösung: `setup_liboqs.sh` neu
ausführen und sicherstellen, dass die HAZARDOUS-Flags in der CMake-Zeile
gesetzt sind. Falls Flag-Namen sich in einer neueren liboqs-Version
geändert haben: `cat vendor/liboqs/CMakeLists.txt | grep -i stfl`.

### `OSError: libliboqs.so: cannot open shared object file`

`LD_LIBRARY_PATH` ist nicht gesetzt. Lösung:
```bash
export LD_LIBRARY_PATH="$(pwd)/vendor/install/lib:${LD_LIBRARY_PATH:-}"
```

### `pytest` sammelt Tests aus `vendor/` ein

Sollte mit der mitgelieferten `pytest.ini` nicht passieren. Falls doch:
sicherstellen, dass `pytest.ini` im Projekt-Root liegt, nicht in
`tests/`.

### `pytest` "hängt" am Anfang

Kein Hang, sondern Wartezeit auf das erste XMSS-keygen
(~3 Sekunden). Mit `pytest -v -s` Live-Output sichtbar machen.

### Pool-Größe in Tests ist 1023 statt 1024

Das ist eine liboqs-Konvention, kein Bug. Der Test akzeptiert beide
Werte. Siehe Methodische Notizen oben.

---

## 8. Lizenzen und Quellen

### Verwendete Bibliotheken

- **liboqs** (Open Quantum Safe), MIT-Lizenz
- **liboqs-python**, MIT-Lizenz
- **pandas, pytest, tabulate** über pip, jeweils eigene Lizenzen

### Kryptographische Standards

- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard
  (ML-DSA, 2024)
- NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard
  (SLH-DSA, 2024)
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature
  Schemes (2020)
- RFC 8391 — XMSS: eXtended Merkle Signature Scheme (2018)

### Weitere Quellen

- Buchmann, Dahmen, Hülsing — *XMSS — A Practical Forward Secure
  Signature Scheme Based on Minimal Security Assumptions*, PQCrypto
  2011
- NSA — Commercial National Security Algorithm Suite 2.0 (CNSA 2.0),
  September 2022
- Thales TCT — *Quantum-Resistant Code Signing Secured by Hardware
  Security Modules*, Whitepaper 2024
- NIST PQC Forum — Diskussion zur SP 800-208 Revision (2024)

---

## Anhang: Status der Arbeit

- [x] Schritt 1: Projekt-Skelett, Wrapper, Smoke-Test
- [x] Schritt 2: Benchmark-Runner mit CSV-Output
- [x] Schritt 3: XMSS-Statefulness-Demos (3 Demos)
- [x] Schritt 4: HSM-Diskussion (`docs/stateful_hsm_discussion.md`)
- [x] Schritt 5: Test-Suite (79 Tests, alle grün)
- [ ] Schritt 6: Ausarbeitung
- [ ] Schritt 7: Präsentation
