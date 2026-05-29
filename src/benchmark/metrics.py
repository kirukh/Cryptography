"""
Mess-Mechanik fuer Performance-Benchmarks.

Designentscheidungen:
- time.perf_counter_ns() statt time.time(): hoechste Aufloesung,
  monotonisch.
- Warmup-Iterationen: erste Messungen sind unzuverlaessig (kalter Cache,
  Branch-Predictor untrainiert, ggf. Lazy-Init in der C-Lib).
- Wir speichern jede Einzelmessung, nicht nur Mean/Median.
- Median als robuste primaere Metrik, Mean+Std als sekundaer.

Bewusste Auslassung - Memory-Footprint:
    Wir messen KEIN Memory. tracemalloc sieht nur den Python-Heap;
    liboqs alloziert die relevanten Datenstrukturen (Hash-Baeume,
    Schluesselmaterial) in C. Eine tracemalloc-basierte Messung waere
    eine Untergrenze ohne aussagekraeftigen Vergleichswert und wuerde
    das Reporting nur belasten. Aus methodischer Ehrlichkeit ist
    'gar nicht messen' hier besser als 'irrefuehrend messen'.
"""
from __future__ import annotations
import gc
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass
class Measurement:
    """Ergebnis einer einzelnen gemessenen Operation."""
    operation: str
    algorithm: str
    iterations: int
    warmup: int
    raw_times_ns: list[int] = field(default_factory=list)

    @property
    def median_ms(self) -> float:
        return statistics.median(self.raw_times_ns) / 1_000_000

    @property
    def mean_ms(self) -> float:
        return statistics.fmean(self.raw_times_ns) / 1_000_000

    @property
    def stdev_ms(self) -> float:
        if len(self.raw_times_ns) < 2:
            return 0.0
        return statistics.stdev(self.raw_times_ns) / 1_000_000

    @property
    def min_ms(self) -> float:
        return min(self.raw_times_ns) / 1_000_000

    @property
    def max_ms(self) -> float:
        return max(self.raw_times_ns) / 1_000_000


def measure(
    operation_name: str,
    algorithm_name: str,
    fn: Callable[[], Any],
    iterations: int = 100,
    warmup: int = 5,
) -> Measurement:
    """Misst die Ausfuehrungszeit von fn() ueber mehrere Iterationen."""
    # Warmup - Ergebnisse verworfen.
    for _ in range(warmup):
        fn()

    # Zeitmessungen.
    gc.collect()
    raw_times: list[int] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        end = time.perf_counter_ns()
        raw_times.append(end - start)

    return Measurement(
        operation=operation_name,
        algorithm=algorithm_name,
        iterations=iterations,
        warmup=warmup,
        raw_times_ns=raw_times,
    )