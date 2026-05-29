"""
Orchestriert die Benchmarks ueber alle drei Algorithmen.

Schreibt drei CSVs:

1. results_summary.csv: Eine Zeile pro (Algorithmus, Operation) mit
   aggregierten Metriken. Geeignet fuer Tabellen in der Ausarbeitung.

2. results_raw.csv: Eine Zeile pro Einzelmessung. Geeignet fuer
   Verteilungsanalysen.

3. results_sizes.csv: PK-, SK- und Signaturgroessen pro Algorithmus.

WICHTIG fuer XMSS:
    Wir verbrauchen pro sign-Benchmark <iterations> Indizes. Bei
    iterations=100 und 2^10=1024 verfuegbaren Indizes ist das
    unkritisch. Pro Lauf wird ein frischer Key erzeugt, der State wird
    nach jedem sign() richtig weitergereicht.

Bewusste Auslassung - Memory-Footprint:
    Wir reporten keinen Memory-Verbrauch. Begruendung siehe
    src/benchmark/metrics.py.
"""
from __future__ import annotations
import csv
from pathlib import Path

from src.algorithms import (
    SignatureScheme,
    MLDSAScheme,
    SLHDSAScheme,
    XMSSScheme,
    XMSSNotEnabledError,
)
from src.benchmark.metrics import Measurement, measure


DEFAULT_SCHEMES_FACTORIES = [
    ("ML-DSA-65",         lambda: MLDSAScheme("ML-DSA-65")),
    ("SLH-DSA-SHA2-128f", lambda: SLHDSAScheme("SLH-DSA-SHA2-128f")),
    ("XMSS-SHA2_10_256",  lambda: XMSSScheme("XMSS-SHA2_10_256")),
]

# Iterations-Defaults pro Operation. XMSS-Keygen kann mehrere Sekunden
# dauern (Build des Hash-Trees), darum dort weniger Iterationen.
DEFAULT_ITERS = {
    "keygen": {"iterations": 20,  "warmup": 2},
    "sign":   {"iterations": 100, "warmup": 5},
    "verify": {"iterations": 100, "warmup": 5},
}

MESSAGE = b"Benchmark message - PQ signature comparison"


def benchmark_scheme(
    scheme: SignatureScheme,
    iters: dict | None = None,
) -> tuple[list[Measurement], dict]:
    """Benchmarkt einen einzelnen Algorithmus."""
    iters = iters or DEFAULT_ITERS

    print(f"\n--- Benchmark: {scheme.name} ---")
    sizes = {
        "algorithm": scheme.name,
        "is_stateful": scheme.is_stateful,
        "public_key_bytes": scheme.public_key_size(),
        "secret_key_bytes": scheme.secret_key_size(),
        "signature_bytes": scheme.signature_size(),
    }
    print(f"  PK={sizes['public_key_bytes']}B  "
          f"SK={sizes['secret_key_bytes']}B  "
          f"Sig={sizes['signature_bytes']}B")

    measurements: list[Measurement] = []

    # 1. KEYGEN
    print(f"  keygen ({iters['keygen']['iterations']} iter)... ",
          end="", flush=True)
    m_keygen = measure(
        "keygen", scheme.name,
        fn=lambda: scheme.keygen(),
        **iters["keygen"],
    )
    measurements.append(m_keygen)
    print(f"median={m_keygen.median_ms:.3f} ms")

    kp = scheme.keygen()
    current_sk = kp.secret_key

    # 2. SIGN - bei XMSS muss der State fortgeschrieben werden.
    sk_state = {"sk": current_sk}

    def do_sign():
        sig, new_sk = scheme.sign(sk_state["sk"], MESSAGE)
        sk_state["sk"] = new_sk
        return sig

    print(f"  sign   ({iters['sign']['iterations']} iter)... ",
          end="", flush=True)
    m_sign = measure(
        "sign", scheme.name,
        fn=do_sign,
        **iters["sign"],
    )
    measurements.append(m_sign)
    print(f"median={m_sign.median_ms:.3f} ms")

    # 3. VERIFY
    sig_for_verify, sk_state["sk"] = scheme.sign(sk_state["sk"], MESSAGE)

    def do_verify():
        return scheme.verify(kp.public_key, MESSAGE, sig_for_verify)

    print(f"  verify ({iters['verify']['iterations']} iter)... ",
          end="", flush=True)
    m_verify = measure(
        "verify", scheme.name,
        fn=do_verify,
        **iters["verify"],
    )
    measurements.append(m_verify)
    print(f"median={m_verify.median_ms:.3f} ms")

    return measurements, sizes


def write_summary_csv(measurements: list[Measurement], path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "algorithm", "operation", "iterations",
            "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms",
        ])
        for m in measurements:
            w.writerow([
                m.algorithm, m.operation, m.iterations,
                f"{m.median_ms:.6f}",
                f"{m.mean_ms:.6f}",
                f"{m.stdev_ms:.6f}",
                f"{m.min_ms:.6f}",
                f"{m.max_ms:.6f}",
            ])
    print(f"  -> {path}")


def write_raw_csv(measurements: list[Measurement], path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "operation", "iteration_index", "duration_ns"])
        for m in measurements:
            for i, t_ns in enumerate(m.raw_times_ns):
                w.writerow([m.algorithm, m.operation, i, t_ns])
    print(f"  -> {path}")


def write_sizes_csv(sizes_list: list[dict], path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "algorithm", "is_stateful",
            "public_key_bytes", "secret_key_bytes", "signature_bytes",
        ])
        for s in sizes_list:
            w.writerow([
                s["algorithm"], s["is_stateful"],
                s["public_key_bytes"], s["secret_key_bytes"],
                s["signature_bytes"],
            ])
    print(f"  -> {path}")


def print_summary_table(measurements: list[Measurement],
                        sizes_list: list[dict]) -> None:
    """Druckt eine konsolidierte Tabelle - bereit zum Abtippen in die
    Ausarbeitung.
    """
    try:
        from tabulate import tabulate
    except ImportError:
        return  # tabulate ist optional fuer dieses Komfortfeature

    print("\n" + "=" * 60)
    print("Performance-Tabelle (Median in ms):")
    print("=" * 60)

    rows = []
    by_algo = {}
    for m in measurements:
        by_algo.setdefault(m.algorithm, {})[m.operation] = m.median_ms

    for algo, ops in by_algo.items():
        rows.append([
            algo,
            f"{ops.get('keygen', 0):.3f}",
            f"{ops.get('sign', 0):.3f}",
            f"{ops.get('verify', 0):.3f}",
        ])
    print(tabulate(rows,
                   headers=["Algorithmus", "keygen", "sign", "verify"],
                   tablefmt="github"))

    print("\n" + "=" * 60)
    print("Groessen-Tabelle (in Bytes):")
    print("=" * 60)
    size_rows = [[
        s["algorithm"],
        "ja" if s["is_stateful"] else "nein",
        s["public_key_bytes"],
        s["secret_key_bytes"],
        s["signature_bytes"],
    ] for s in sizes_list]
    print(tabulate(size_rows,
                   headers=["Algorithmus", "stateful", "PK", "SK", "Sig"],
                   tablefmt="github"))


def run_full_benchmark(
    scheme_factories=None,
    output_dir: Path | str = "results",
    iters: dict | None = None,
) -> None:
    """Fuehrt alle Benchmarks durch und schreibt CSVs."""
    scheme_factories = scheme_factories or DEFAULT_SCHEMES_FACTORIES
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    all_measurements: list[Measurement] = []
    all_sizes: list[dict] = []

    print("=" * 60)
    print("Benchmark-Lauf")
    print("=" * 60)

    for label, factory in scheme_factories:
        try:
            scheme = factory()
        except XMSSNotEnabledError as e:
            print(f"\n--- {label} UEBERSPRUNGEN ---")
            print(f"  {e}")
            continue
        except Exception as e:
            print(f"\n--- {label} FEHLER ---")
            print(f"  {type(e).__name__}: {e}")
            continue

        measurements, sizes = benchmark_scheme(scheme, iters=iters)
        all_measurements.extend(measurements)
        all_sizes.append(sizes)

    print("\n" + "=" * 60)
    print("Schreibe Ergebnisse:")
    print("=" * 60)
    write_summary_csv(all_measurements, out / "results_summary.csv")
    write_raw_csv(all_measurements, out / "results_raw.csv")
    write_sizes_csv(all_sizes, out / "results_sizes.csv")

    print_summary_table(all_measurements, all_sizes)
    print("\nFertig.")