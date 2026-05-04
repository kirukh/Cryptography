"""
Smoke-Tests fuer die Plot-Generierung.

Wir wollen NICHT die Pixel der Plots vergleichen - das waere fragil
und sagt wenig aus. Stattdessen pruefen wir:
- Plot-Funktionen laufen ohne Exception durch.
- PNG-Dateien werden tatsaechlich erzeugt.
- Erzeugte PNGs sind nicht leer.
- generate_all_plots() arbeitet defensiv: fehlt eine CSV, gibt es
  eine Warnung statt eines Crashes.

Hintergrund: matplotlib-Plots zu vergleichen ist eine eigene
Wissenschaft. Wir verlassen uns hier auf das Smoke-Test-Prinzip:
'lief der Code durch und kam etwas Plausibles raus' reicht.
"""
from __future__ import annotations
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # keine Display-Pflicht in CI/Tests

import pytest

from src.visualization.plots import (
    plot_bar_times,
    plot_bar_sizes,
    plot_boxplot_per_operation,
    generate_all_plots,
)


# ----------------------------------------------------------------------
# Helfer: Mini-CSVs bauen, die das Schema von runner.py treffen
# ----------------------------------------------------------------------

def _write_summary_csv(path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "algorithm", "operation", "iterations",
            "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms",
            "peak_memory_bytes",
        ])
        for algo in ("ML-DSA-65", "SLH-DSA-SHA2-128f", "XMSS-SHA2_10_256"):
            for op, t in (("keygen", 0.5), ("sign", 0.2), ("verify", 0.1)):
                w.writerow([algo, op, 10, t, t, 0.01, t * 0.9, t * 1.1, 1024])


def _write_raw_csv(path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "operation", "iteration_index", "duration_ns"])
        for algo in ("ML-DSA-65", "SLH-DSA-SHA2-128f", "XMSS-SHA2_10_256"):
            for op in ("keygen", "sign", "verify"):
                for i in range(10):
                    # Ein bisschen Variation einbauen
                    w.writerow([algo, op, i, 1_000_000 + i * 100_000])


def _write_sizes_csv(path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "algorithm", "is_stateful",
            "public_key_bytes", "secret_key_bytes", "signature_bytes",
        ])
        w.writerow(["ML-DSA-65", "False", 1952, 4032, 3309])
        w.writerow(["SLH-DSA-SHA2-128f", "False", 32, 64, 17088])
        w.writerow(["XMSS-SHA2_10_256", "True", 64, 1373, 2500])


# ======================================================================
# Einzelne Plot-Funktionen
# ======================================================================

class TestPlotBarTimes:
    def test_creates_png(self, tmp_path):
        summary = tmp_path / "summary.csv"
        _write_summary_csv(summary)
        out = tmp_path / "bar.png"

        plot_bar_times(summary, out)

        assert out.exists()
        assert out.stat().st_size > 0

    def test_handles_partial_data(self, tmp_path):
        """Wenn nur 2 von 3 Algorithmen Daten haben, soll trotzdem ein
        Plot rauskommen.
        """
        summary = tmp_path / "summary.csv"
        with summary.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "algorithm", "operation", "iterations",
                "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms",
                "peak_memory_bytes",
            ])
            for op in ("keygen", "sign", "verify"):
                w.writerow(["ML-DSA-65", op, 10, 0.5, 0.5, 0.01, 0.4, 0.6, 1024])
                w.writerow(["SLH-DSA-SHA2-128f", op, 10, 5.0, 5.0, 0.5, 4.5, 5.5, 2048])

        out = tmp_path / "bar_partial.png"
        plot_bar_times(summary, out)
        assert out.exists()


class TestPlotBarSizes:
    def test_creates_png(self, tmp_path):
        sizes = tmp_path / "sizes.csv"
        _write_sizes_csv(sizes)
        out = tmp_path / "sizes.png"

        plot_bar_sizes(sizes, out)

        assert out.exists()
        assert out.stat().st_size > 0


class TestBoxplots:
    def test_creates_one_png_per_operation(self, tmp_path):
        raw = tmp_path / "raw.csv"
        _write_raw_csv(raw)

        plot_boxplot_per_operation(raw, tmp_path)

        for op in ("keygen", "sign", "verify"):
            box_path = tmp_path / f"box_{op}.png"
            assert box_path.exists(), f"Box-Plot fuer '{op}' fehlt"
            assert box_path.stat().st_size > 0


# ======================================================================
# generate_all_plots Orchestrator
# ======================================================================

class TestGenerateAllPlots:
    def test_full_pipeline(self, tmp_path):
        _write_summary_csv(tmp_path / "results_summary.csv")
        _write_raw_csv(tmp_path / "results_raw.csv")
        _write_sizes_csv(tmp_path / "results_sizes.csv")

        generate_all_plots(tmp_path)

        # bar_times, bar_sizes, box_keygen, box_sign, box_verify -> 5 PNGs
        pngs = list(tmp_path.glob("*.png"))
        assert len(pngs) == 5

    def test_handles_missing_csvs_gracefully(self, tmp_path, capsys):
        """generate_all_plots darf NICHT crashen wenn eine CSV fehlt -
        es soll nur eine Warnung ausgeben.
        """
        # Nur summary.csv vorhanden, raw und sizes fehlen
        _write_summary_csv(tmp_path / "results_summary.csv")

        # Darf keinen Crash werfen
        generate_all_plots(tmp_path)

        captured = capsys.readouterr()
        assert "WARNUNG" in captured.out
