"""
Gibt die Umgebungs-Informationen fuer den Reproduzierbarkeits-Abschnitt
der Ausarbeitung aus: CPU, RAM, OS, Python- und liboqs-Versionen.

Die Ausgabe kann 1:1 in das Methodik-Kapitel uebernommen werden
(siehe README, Abschnitt 6.1).

Aufruf:
    python -m src.env_info
"""
from __future__ import annotations
import platform
import sys

import psutil


def _cpu_model() -> str:
    """CPU-Modellname; unter Linux/WSL aus /proc/cpuinfo."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unbekannt"


def main() -> None:
    print("=" * 60)
    print("Umgebungs-Info (fuer Ausarbeitung, Abschnitt Reproduzierbarkeit)")
    print("=" * 60)

    print(f"CPU             : {_cpu_model()}")
    print(f"Kerne           : {psutil.cpu_count(logical=False)} physisch / "
          f"{psutil.cpu_count(logical=True)} logisch")
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    print(f"RAM             : {ram_gb:.1f} GiB")
    print(f"OS              : {platform.system()} {platform.release()}")
    print(f"Plattform       : {platform.platform()}")
    print(f"Python          : {sys.version.split()[0]}")

    # liboqs-Versionen, falls verfuegbar
    try:
        import oqs
        print(f"liboqs (C)      : {oqs.oqs_version()}")
        try:
            print(f"liboqs-python   : {oqs.oqs_python_version()}")
        except Exception:
            print("liboqs-python   : (Version nicht abfragbar)")
    except ImportError:
        print("liboqs          : nicht installiert / nicht im Pfad")


if __name__ == "__main__":
    main()
