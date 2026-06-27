# Fixes (Review-Runde vor Abgabe)

Alle Dateien in diesem Archiv 1:1 in das Projekt kopieren
(Pfade entsprechen der Projektstruktur, bestehende Dateien
ueberschreiben).

## Geaenderte Dateien

| Datei | Aenderung |
|---|---|
| `src/algorithms/sphincs_wrapper.py` | Faktenfehler korrigiert: "CRYSTALS-SPHINCS+" -> "SPHINCS+" (SPHINCS+ gehoerte nie zur CRYSTALS-Familie; CRYSTALS = Kyber + Dilithium) |
| `src/stateful_demo/run_all.py` | Demo 1 (Index-Progression) eingebunden |
| `src/stateful_demo/__init__.py` | Docstring: vier Demos statt drei, Demo 1 gelistet |
| `src/benchmark/runner.py` | Kommentar zum Index-Verbrauch korrigiert (106 statt 100); methodischer Hinweis zum Wrapper-Overhead im Docstring ergaenzt |
| `src/env_info.py` | NEU: gibt CPU/RAM/OS/Versionen fuer den Reproduzierbarkeits-Abschnitt aus (`python -m src.env_info`); nutzt das bisher ungenutzte psutil |
| `requirements.txt` | psutil-Verwendungszweck dokumentiert |
| `README.md` | Demo 1 in Projektstruktur, 4.3 und neuem Abschnitt 5.3 (Folgeabschnitte umnummeriert auf 5.4-5.7); Abschnitt 4.4 (env_info); Wrapper-Overhead in 5.2 und 6.5; Limitation Nr. 7 in 6.7; Demo-1-Zeile in 6.6; "4 Demos" im Status-Anhang; psutil in Lizenzliste |

## Nicht geaendert (bewusst)

- Demo 2: die narrative Unschaerfe (msg_a wird ebenfalls vom Snapshot
  signiert) ist kryptographisch irrelevant. Falls gewuenscht, in der
  Ausarbeitung den Vergleich gegen die gespeicherte legit-1-Signatur
  beschreiben statt die Demo anzufassen.
- pytest-Marker `slow`/`integration`: bleiben als dokumentierter
  Platzhalter fuer den ausgelassenen Pool-Leerungs-Test.
