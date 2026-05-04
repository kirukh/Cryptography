"""
Tests fuer src/benchmark/metrics.py und src/benchmark/runner.py.

Wir testen:
- Measurement-Statistiken sind korrekt (median, mean, min, max).
- measure() erfasst die richtige Anzahl raw_times.
- Warmup-Iterationen werden NICHT in raw_times aufgenommen.
- Memory-Tracking ist optional und beeinflusst die Zeitmessung nicht.
- CSV-Output von runner hat das erwartete Schema.

Wir nutzen ueberall NICHT die echten Krypto-Operationen, sondern
eine winzige Dummy-Funktion. So sind die Tests deterministisch und
schnell.
"""
from __future__ import annotations
import csv
import time
from pathlib import Path

import pytest

from src.benchmark.metrics import Measurement, measure
from src.benchmark.runner import (
    write_summary_csv,
    write_raw_csv,
    write_sizes_csv,
)


# ======================================================================
# Measurement Datenklasse
# ======================================================================

class TestMeasurementStatistics:
    def test_median_correct(self):
        m = Measurement(
            operation="x", algorithm="dummy",
            iterations=5, warmup=0,
            raw_times_ns=[1_000_000, 2_000_000, 3_000_000,
                          4_000_000, 5_000_000],
        )
        # Median in ms: 3_000_000 ns / 1e6 = 3.0
        assert m.median_ms == pytest.approx(3.0)

    def test_mean_correct(self):
        m = Measurement(
            operation="x", algorithm="dummy",
            iterations=4, warmup=0,
            raw_times_ns=[1_000_000, 2_000_000, 3_000_000, 4_000_000],
        )
        # Mean: 2.5 ms
        assert m.mean_ms == pytest.approx(2.5)

    def test_min_max(self):
        m = Measurement(
            operation="x", algorithm="dummy",
            iterations=3, warmup=0,
            raw_times_ns=[5_000_000, 1_000_000, 9_000_000],
        )
        assert m.min_ms == pytest.approx(1.0)
        assert m.max_ms == pytest.approx(9.0)

    def test_stdev_zero_for_single_value(self):
        """Bei genau einem Wert ist die Standardabweichung undefiniert.

        Wir haben das in metrics.py auf 0.0 gesetzt - das pruefen wir hier.
        """
        m = Measurement(
            operation="x", algorithm="dummy",
            iterations=1, warmup=0,
            raw_times_ns=[1_000_000],
        )
        assert m.stdev_ms == 0.0

    def test_stdev_nonzero_for_varying_values(self):
        m = Measurement(
            operation="x", algorithm="dummy",
            iterations=4, warmup=0,
            raw_times_ns=[1_000_000, 2_000_000, 3_000_000, 4_000_000],
        )
        assert m.stdev_ms > 0


# ======================================================================
# measure()
# ======================================================================

class TestMeasureFunction:
    def test_records_correct_iteration_count(self):
        counter = {"n": 0}

        def fn():
            counter["n"] += 1

        m = measure("op", "alg", fn, iterations=10, warmup=0,
                    measure_memory=False)
        assert len(m.raw_times_ns) == 10

    def test_warmup_not_in_raw_times(self):
        """Warmup-Aufrufe duerfen NICHT in raw_times_ns landen.

        Wir koennen das pruefen, indem wir den Counter zaehlen lassen,
        wie oft fn() insgesamt aufgerufen wird vs. wie viele Raw-Times
        landen am Ende drin.
        """
        counter = {"n": 0}

        def fn():
            counter["n"] += 1

        m = measure("op", "alg", fn, iterations=5, warmup=3,
                    measure_memory=False)
        # Funktion wurde 5 (iter) + 3 (warmup) = 8 mal aufgerufen
        assert counter["n"] == 8
        # ABER raw_times enthaelt nur die 5 echten Messungen
        assert len(m.raw_times_ns) == 5

    def test_measure_memory_does_extra_call(self):
        """Mit measure_memory=True macht measure() einen zusaetzlichen
        fn()-Aufruf fuer das tracemalloc-Sampling.
        """
        counter = {"n": 0}

        def fn():
            counter["n"] += 1

        measure("op", "alg", fn, iterations=5, warmup=0,
                measure_memory=True)
        # 5 (iter) + 1 (memory) = 6
        assert counter["n"] == 6

    def test_records_positive_durations(self):
        """Alle gemessenen Zeiten muessen >= 0 sein."""
        def fn():
            # Ein bisschen Arbeit, damit perf_counter_ns garantiert > 0 misst
            sum(range(100))

        m = measure("op", "alg", fn, iterations=20, warmup=2,
                    measure_memory=False)
        assert all(t >= 0 for t in m.raw_times_ns)

    def test_metadata_propagates(self):
        m = measure("keygen", "TEST-ALG", lambda: None,
                    iterations=3, warmup=1, measure_memory=False)
        assert m.operation == "keygen"
        assert m.algorithm == "TEST-ALG"
        assert m.iterations == 3
        assert m.warmup == 1


# ======================================================================
# CSV-Writer
# ======================================================================

class TestCsvWriters:
    @pytest.fixture
    def sample_measurements(self):
        return [
            Measurement(
                operation="keygen", algorithm="ALG-A",
                iterations=3, warmup=1,
                raw_times_ns=[1_000_000, 2_000_000, 3_000_000],
                peak_memory_bytes=1024,
            ),
            Measurement(
                operation="sign", algorithm="ALG-A",
                iterations=2, warmup=0,
                raw_times_ns=[5_000_000, 6_000_000],
                peak_memory_bytes=2048,
            ),
        ]

    def test_summary_csv_schema(self, sample_measurements, tmp_path):
        out = tmp_path / "summary.csv"
        write_summary_csv(sample_measurements, out)
        assert out.exists()

        with out.open() as f:
            reader = csv.DictReader(f)
            expected_columns = {
                "algorithm", "operation", "iterations",
                "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms",
                "peak_memory_bytes",
            }
            assert set(reader.fieldnames) == expected_columns
            rows = list(reader)
            assert len(rows) == 2

    def test_summary_csv_values(self, sample_measurements, tmp_path):
        out = tmp_path / "summary.csv"
        write_summary_csv(sample_measurements, out)

        with out.open() as f:
            rows = list(csv.DictReader(f))

        keygen_row = next(r for r in rows if r["operation"] == "keygen")
        # Median von [1, 2, 3] ms ist 2.0
        assert float(keygen_row["median_ms"]) == pytest.approx(2.0)
        assert keygen_row["algorithm"] == "ALG-A"
        assert int(keygen_row["peak_memory_bytes"]) == 1024

    def test_raw_csv_one_row_per_measurement(
        self, sample_measurements, tmp_path
    ):
        out = tmp_path / "raw.csv"
        write_raw_csv(sample_measurements, out)

        with out.open() as f:
            rows = list(csv.DictReader(f))

        # 3 (keygen) + 2 (sign) = 5 Zeilen
        assert len(rows) == 5

    def test_raw_csv_iteration_indices_are_consecutive(
        self, sample_measurements, tmp_path
    ):
        out = tmp_path / "raw.csv"
        write_raw_csv(sample_measurements, out)

        with out.open() as f:
            rows = list(csv.DictReader(f))

        keygen_rows = [r for r in rows if r["operation"] == "keygen"]
        indices = [int(r["iteration_index"]) for r in keygen_rows]
        assert indices == [0, 1, 2]

    def test_sizes_csv_schema(self, tmp_path):
        sizes = [
            {
                "algorithm": "ALG-A", "is_stateful": False,
                "public_key_bytes": 100, "secret_key_bytes": 200,
                "signature_bytes": 300,
            },
        ]
        out = tmp_path / "sizes.csv"
        write_sizes_csv(sizes, out)

        with out.open() as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 1
        row = rows[0]
        assert row["algorithm"] == "ALG-A"
        assert row["is_stateful"] == "False"
        assert int(row["public_key_bytes"]) == 100
        assert int(row["signature_bytes"]) == 300
