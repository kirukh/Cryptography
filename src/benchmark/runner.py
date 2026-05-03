"""
Orchestriert die Benchmarks ueber alle drei Algorithmen.

Schreibt ZWEI CSVs:

1. results_summary.csv:
       Eine Zeile pro (Algorithmus, Operation) mit aggregierten Metriken.
       Geeignet fuer Bar-Charts, Tabellen in der Ausarbeitung.

2. results_raw.csv:
       Eine Zeile pro Einzelmessung. Geeignet fuer Box-Plots und
       Verteilungsanalysen.

Plus eine Schluesselgroessen-Tabelle als drittes CSV:
3. results_sizes.csv:
       PK-, SK- und Signaturgroessen pro Algorithmus.

WICHTIG fuer XMSS:
    Wir verbrauchen pro sign-Benchmark <iterations> Indizes des Keys.
    Bei iterations=100 und 2^10=1024 verfuegbaren Indizes ist das
    unkritisch. Wir generieren pro Lauf einen frischen Key und nutzen
    ihn dann komplett auf - der State wird nach jedem sign() richtig
    weitergereicht.
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


# Standard-Konfiguration fuer Schritt 2: kleiner Lauf mit Defaults.
DEFAULT_SCHEMES_FACTORIES = [
    ("ML-DSA-65",        lambda: MLDSAScheme("ML-DSA-65")),
    ("SLH-DSA-SHA2-128f", lambda: SLHDSAScheme("SLH-DSA-SHA2-128f")),
    ("XMSS-SHA2_10_256", lambda: XMSSScheme("XMSS-SHA2_10_256")),
]

# Iterations-Defaults pro Operation.
# SLH-DSA-Sign ist deutlich langsamer als ML-DSA-Sign, daher sind 100
# Iterationen eine guter Kompromiss: bei ML-DSA noch schnell durch,
# bei SLH-DSA-128f dauert das ~5-10 Sekunden insgesamt.
# XMSS-Keygen kann je nach Maschine schon mehrere Sekunden dauern
# (Build des Hash-Trees), darum dort weniger Iterationen.
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
    """Benchmarkt einen einzelnen Algorithmus.

    Returns:
        (measurements, sizes_dict)
    """
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
    print(f"  keygen ({iters['keygen']['iterations']} iter)... ", end="", flush=True)
    m_keygen = measure(
        "keygen", scheme.name,
        fn=lambda: scheme.keygen(),
        **iters["keygen"],
    )
    measurements.append(m_keygen)
    print(f"median={m_keygen.median_ms:.3f} ms")

    # Wir brauchen ein Schluesselpaar fuer sign/verify-Benchmarks.
    kp = scheme.keygen()
    current_sk = kp.secret_key

    # 2. SIGN
    # Bei XMSS muss der State fortgeschrieben werden. Wir verwalten
    # einen mutierbaren Container, damit die Closure den State sieht.
    sk_state = {"sk": current_sk}

    def do_sign():
        sig, new_sk = scheme.sign(sk_state["sk"], MESSAGE)
        sk_state["sk"] = new_sk
        return sig

    print(f"  sign   ({iters['sign']['iterations']} iter)... ", end="", flush=True)
    m_sign = measure(
        "sign", scheme.name,
        fn=do_sign,
        **iters["sign"],
    )
    measurements.append(m_sign)
    print(f"median={m_sign.median_ms:.3f} ms")

    # 3. VERIFY (stateless, wir nehmen eine repraesentative Signatur)
    sig_for_verify, sk_state["sk"] = scheme.sign(sk_state["sk"], MESSAGE)

    def do_verify():
        return scheme.verify(kp.public_key, MESSAGE, sig_for_verify)

    print(f"  verify ({iters['verify']['iterations']} iter)... ", end="", flush=True)
    m_verify = measure(
        "verify", scheme.name,
        fn=do_verify,
        **iters["verify"],
    )
    measurements.append(m_verify)
    print(f"median={m_verify.median_ms:.3f} ms")

    return measurements, sizes


def write_summary_csv(measurements: list[Measurement], path: Path) -> None:
    """Schreibt aggregierte Metriken: eine Zeile pro (Algo, Operation)."""
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "algorithm", "operation", "iterations",
            "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms",
            "peak_memory_bytes",
        ])
        for m in measurements:
            w.writerow([
                m.algorithm, m.operation, m.iterations,
                f"{m.median_ms:.6f}",
                f"{m.mean_ms:.6f}",
                f"{m.stdev_ms:.6f}",
                f"{m.min_ms:.6f}",
                f"{m.max_ms:.6f}",
                m.peak_memory_bytes,
            ])
    print(f"  -> {path}")


def write_raw_csv(measurements: list[Measurement], path: Path) -> None:
    """Schreibt jede Einzelmessung - Basis fuer Box-Plots."""
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "operation", "iteration_index", "duration_ns"])
        for m in measurements:
            for i, t_ns in enumerate(m.raw_times_ns):
                w.writerow([m.algorithm, m.operation, i, t_ns])
    print(f"  -> {path}")


def write_sizes_csv(sizes_list: list[dict], path: Path) -> None:
    """Schreibt PK/SK/Sig-Groessen."""
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "algorithm", "is_stateful",
            "public_key_bytes", "secret_key_bytes", "signature_bytes",
        ])
        for s in sizes_list:
            w.writerow([
                s["algorithm"], s["is_stateful"],
                s["public_key_bytes"], s["secret_key_bytes"], s["signature_bytes"],
            ])
    print(f"  -> {path}")


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
    print("\nFertig.")
