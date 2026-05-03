"""
Entry-Point fuer den kompletten Schritt-2-Lauf.

Aufruf:
    cd pq-bench
    python -m src.run_benchmark

Optional:
    python -m src.run_benchmark --no-plots     # nur Benchmark, keine PNGs
    python -m src.run_benchmark --plots-only   # nur Plots aus vorhandenem CSV
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from src.benchmark.runner import run_full_benchmark
from src.visualization.plots import generate_all_plots


def main() -> int:
    parser = argparse.ArgumentParser(description="PQ-Signature Benchmark")
    parser.add_argument(
        "--results-dir", default="results",
        help="Output-Verzeichnis fuer CSVs und Plots (default: results)",
    )
    parser.add_argument(
        "--no-plots", action="store_true",
        help="Nur Benchmark ausfuehren, keine Plots erzeugen.",
    )
    parser.add_argument(
        "--plots-only", action="store_true",
        help="Nur Plots aus existierenden CSVs erzeugen, keinen Benchmark.",
    )
    args = parser.parse_args()

    out = Path(args.results_dir)

    if not args.plots_only:
        run_full_benchmark(output_dir=out)

    if not args.no_plots:
        print()
        generate_all_plots(out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
