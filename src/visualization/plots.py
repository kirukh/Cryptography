"""
Plots aus den Benchmark-CSVs.

Erzeugt:
- bar_times.png       : Median-Laufzeit pro Operation (gruppiert)
- bar_sizes.png       : PK / SK / Signatur Groessen (gruppiert, log-Skala)
- box_<operation>.png : Box-Plots der Verteilung pro Operation
                        (keygen, sign, verify einzeln)

Nutzt nur matplotlib + pandas, keine seaborn-Abhaengigkeit.
"""
from __future__ import annotations
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


# Konsistente Farben pro Algorithmus, damit Plots vergleichbar sind.
COLOR_MAP = {
    "ML-DSA-65":         "#1f77b4",
    "SLH-DSA-SHA2-128f": "#d62728",
    "XMSS-SHA2_10_256":  "#2ca02c",
}

# Reihenfolge fuer konsistente Anordnung in Plots.
ALGO_ORDER = ["ML-DSA-65", "SLH-DSA-SHA2-128f", "XMSS-SHA2_10_256"]
OP_ORDER = ["keygen", "sign", "verify"]


def _color_for(algo: str) -> str:
    return COLOR_MAP.get(algo, "#7f7f7f")


def plot_bar_times(summary_csv: Path, output: Path) -> None:
    """Bar-Chart: Median-Laufzeit pro Operation, gruppiert nach Algorithmus.

    Log-Skala auf der Y-Achse, weil ML-DSA und SLH-DSA mehrere
    Groessenordnungen auseinander liegen koennen (sign-Zeit).
    """
    df = pd.read_csv(summary_csv)

    # Pivot: rows=operation, columns=algorithm, values=median_ms
    pivot = df.pivot_table(
        index="operation", columns="algorithm", values="median_ms"
    )
    # Ordnung erzwingen
    pivot = pivot.reindex(index=[op for op in OP_ORDER if op in pivot.index])
    pivot = pivot.reindex(columns=[a for a in ALGO_ORDER if a in pivot.columns])

    fig, ax = plt.subplots(figsize=(8, 5))
    pivot.plot(
        kind="bar",
        ax=ax,
        color=[_color_for(c) for c in pivot.columns],
        edgecolor="black",
        linewidth=0.5,
    )
    ax.set_yscale("log")
    ax.set_ylabel("Laufzeit (ms, log-Skala)")
    ax.set_xlabel("Operation")
    ax.set_title("Median-Laufzeiten: keygen / sign / verify")
    ax.grid(True, axis="y", which="both", linestyle="--", alpha=0.4)
    ax.legend(title="Algorithmus", loc="upper right")
    plt.setp(ax.get_xticklabels(), rotation=0)

    # Zahlenwerte auf die Balken schreiben
    for container in ax.containers:
        ax.bar_label(container, fmt="%.2f", padding=3, fontsize=7)

    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    print(f"  -> {output}")


def plot_bar_sizes(sizes_csv: Path, output: Path) -> None:
    """Bar-Chart: PK / SK / Signatur Groessen, log-Skala."""
    df = pd.read_csv(sizes_csv)
    df = df.set_index("algorithm").reindex(
        [a for a in ALGO_ORDER if a in df["algorithm"].values
         or a in df.index]
    )
    cols = ["public_key_bytes", "secret_key_bytes", "signature_bytes"]
    pretty = {
        "public_key_bytes": "Public Key",
        "secret_key_bytes": "Secret Key",
        "signature_bytes":  "Signatur",
    }
    plot_df = df[cols].rename(columns=pretty)

    fig, ax = plt.subplots(figsize=(8, 5))
    plot_df.plot(
        kind="bar",
        ax=ax,
        edgecolor="black",
        linewidth=0.5,
        color=["#4c72b0", "#dd8452", "#55a868"],
    )
    ax.set_yscale("log")
    ax.set_ylabel("Groesse in Bytes (log-Skala)")
    ax.set_xlabel("Algorithmus")
    ax.set_title("Schluessel- und Signaturgroessen")
    ax.grid(True, axis="y", which="both", linestyle="--", alpha=0.4)
    plt.setp(ax.get_xticklabels(), rotation=15, ha="right")

    for container in ax.containers:
        ax.bar_label(container, fmt="%d", padding=3, fontsize=7)

    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    print(f"  -> {output}")


def plot_boxplot_per_operation(raw_csv: Path, output_dir: Path) -> None:
    """Box-Plot pro Operation, ein PNG pro Operation."""
    df = pd.read_csv(raw_csv)
    df["duration_ms"] = df["duration_ns"] / 1_000_000

    for op in OP_ORDER:
        op_df = df[df["operation"] == op]
        if op_df.empty:
            continue

        # Daten pro Algorithmus sammeln, in der gewuenschten Reihenfolge.
        algos_present = [a for a in ALGO_ORDER if a in op_df["algorithm"].unique()]
        data = [op_df[op_df["algorithm"] == a]["duration_ms"].values
                for a in algos_present]

        fig, ax = plt.subplots(figsize=(8, 5))
        bp = ax.boxplot(
            data,
            tick_labels=algos_present,
            patch_artist=True,
            showmeans=True,
            meanprops={"marker": "D", "markerfacecolor": "white",
                       "markeredgecolor": "black", "markersize": 5},
        )

        for patch, algo in zip(bp["boxes"], algos_present):
            patch.set_facecolor(_color_for(algo))
            patch.set_alpha(0.6)

        ax.set_ylabel("Laufzeit (ms)")
        ax.set_title(f"Verteilung der {op}-Laufzeiten")
        ax.grid(True, axis="y", linestyle="--", alpha=0.4)
        plt.setp(ax.get_xticklabels(), rotation=15, ha="right")

        # Bei sehr unterschiedlichen Skalen log-Achse zuschalten,
        # falls Max/Min mehr als Faktor 100 auseinander liegen.
        all_vals = op_df["duration_ms"]
        if len(all_vals) > 0 and all_vals.min() > 0 and all_vals.max() / all_vals.min() > 100:
            ax.set_yscale("log")
            ax.set_ylabel("Laufzeit (ms, log-Skala)")

        fig.tight_layout()
        out_path = output_dir / f"box_{op}.png"
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        print(f"  -> {out_path}")


def generate_all_plots(results_dir: Path | str = "results") -> None:
    """Erzeugt alle Plots aus den drei CSVs in results_dir."""
    out = Path(results_dir)

    summary_csv = out / "results_summary.csv"
    raw_csv = out / "results_raw.csv"
    sizes_csv = out / "results_sizes.csv"

    print("=" * 60)
    print("Erzeuge Plots")
    print("=" * 60)

    if summary_csv.exists():
        plot_bar_times(summary_csv, out / "bar_times.png")
    else:
        print(f"  WARNUNG: {summary_csv} nicht gefunden")

    if sizes_csv.exists():
        plot_bar_sizes(sizes_csv, out / "bar_sizes.png")
    else:
        print(f"  WARNUNG: {sizes_csv} nicht gefunden")

    if raw_csv.exists():
        plot_boxplot_per_operation(raw_csv, out)
    else:
        print(f"  WARNUNG: {raw_csv} nicht gefunden")

    print("\nFertig.")
