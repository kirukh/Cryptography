# pq-bench

Vergleich und Benchmark der Post-Quantum-Signaturverfahren **XMSS**, **ML-DSA**
und **SPHINCS+**, mit besonderem Fokus auf die Statefulness-Problematik
von XMSS.

## Status

- [x] Schritt 1: Projekt-Skelett, Wrapper, Smoke-Test
- [ ] Schritt 2: Benchmark-Runner mit Metriken
- [ ] Schritt 3: Plots
- [ ] Schritt 4: XMSS-Statefulness-Demos
- [ ] Schritt 5: HSM-Diskussion + Ausarbeitung
- [ ] Schritt 6: Praesentation

## Systemvoraussetzungen

**Empfohlen: WSL2 mit Ubuntu 22.04** auf Windows 11.

```powershell
# In Windows-PowerShell (als Admin), falls noch nicht installiert:
wsl --install -d Ubuntu-22.04
```

Anschliessend in der Ubuntu-Shell:

```bash
sudo apt update
sudo apt install -y build-essential cmake git ninja-build \
    libssl-dev python3 python3-pip python3-venv python3-dev pkg-config \
    astyle gcc libtool unzip wget
```

## Installation

```bash
# 1. In WSL2-Ubuntu, Projektordner waehlen
cd ~/projects   # oder wo immer du arbeiten willst
git clone <dein-repo> pq-bench   # falls schon ein Repo existiert
cd pq-bench

# 2. Python-venv anlegen
python3 -m venv .venv
source .venv/bin/activate

# 3. Python-Pakete installieren (ohne liboqs-python aus PyPI!)
pip install --upgrade pip
pip install -r requirements.txt

# 4. liboqs MIT XMSS-Support bauen + liboqs-python installieren
bash setup_liboqs.sh

# 5. WICHTIG: Library-Pfad setzen, damit liboqs zur Laufzeit gefunden wird
export LD_LIBRARY_PATH="$(pwd)/vendor/install/lib:${LD_LIBRARY_PATH:-}"
# Tipp: in ~/.bashrc dauerhaft setzen

# 6. Smoke-Test
python -m src.smoke_test
```

## Erwartete Ausgabe

Wenn alles klappt, siehst du fuer alle drei Algorithmen "OK". Falls XMSS
"UEBERSPRUNGEN" zeigt, ist liboqs ohne XMSS-Support gebaut worden — dann
`setup_liboqs.sh` erneut ausfuehren oder die CMake-Flags pruefen.

## VSCode-Integration (Windows 11 + WSL)

1. Extension **Remote - WSL** installieren
2. In WSL-Ubuntu: `code .` im Projektordner
3. Python-Interpreter auf `.venv/bin/python` setzen
4. `LD_LIBRARY_PATH` in `.vscode/settings.json` hinterlegen:

```json
{
    "python.defaultInterpreterPath": ".venv/bin/python",
    "terminal.integrated.env.linux": {
        "LD_LIBRARY_PATH": "${workspaceFolder}/vendor/install/lib"
    }
}
```

## Projektstruktur

```
pq-bench/
├── src/
│   ├── algorithms/         # Wrapper fuer die drei Verfahren
│   │   ├── base.py         #   Abstraktes Interface
│   │   ├── mldsa_wrapper.py
│   │   ├── sphincs_wrapper.py
│   │   └── xmss_wrapper.py
│   ├── benchmark/          # (Schritt 2) Mess-Logik
│   ├── stateful_demo/      # (Schritt 4) XMSS-Demos
│   ├── visualization/      # (Schritt 3) Plots
│   └── smoke_test.py       # Roundtrip-Test
├── results/                # CSV / PNG Output
├── vendor/                 # liboqs + liboqs-python (gebaut)
├── tests/
└── setup_liboqs.sh
```

## Warum dieser Stack?

- **liboqs** ist die Referenz-Sammlung fuer PQ-Algorithmen, gepflegt vom
  Open-Quantum-Safe-Projekt.
- **XMSS ist in liboqs standardmaessig deaktiviert**, weil es stateful ist
  und Fehlnutzung katastrophal ist. Wir aktivieren es bewusst — und genau
  diese Designentscheidung von liboqs ist ein Argument fuer die Arbeit.
- WSL2 statt nativem Windows: Build-System aller drei Referenzen ist auf
  POSIX ausgelegt, native Windows-Builds sind extrem fehleranfaellig.
