"""
Entry-Point fuer den Benchmark-Lauf.

Aufruf:
    cd pq-bench
    python -m src.run_benchmark            # CSVs + Plots
    python -m src.run_benchmark --no-plots # nur CSVs
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from src.benchmark.runner import run_full_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="PQ-Signature Benchmark")
    parser.add_argument(
        "--results-dir", default="results",
        help="Output-Verzeichnis fuer CSVs/Plots (default: results)",
    )
    parser.add_argument(
        "--no-plots", action="store_true",
        help="Nur CSVs schreiben, keine PNG-Plots erzeugen",
    )
    args = parser.parse_args()
    results_dir = Path(args.results_dir)

    run_full_benchmark(output_dir=results_dir)

    if not args.no_plots:
        try:
            from src.visualization import generate_all_plots
            generate_all_plots(results_dir)
        except ImportError:
            print("\n[Hinweis] matplotlib nicht installiert - Plots uebersprungen.")
            print("          Installiere mit: pip install matplotlib")
    return 0


if __name__ == "__main__":
    sys.exit(main())