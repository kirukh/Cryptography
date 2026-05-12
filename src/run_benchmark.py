"""
Entry-Point fuer den Benchmark-Lauf.

Aufruf:
    cd pq-bench
    python -m src.run_benchmark
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
        help="Output-Verzeichnis fuer CSVs (default: results)",
    )
    args = parser.parse_args()
    run_full_benchmark(output_dir=Path(args.results_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
