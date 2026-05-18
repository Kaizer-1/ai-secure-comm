"""Benchmark AES-256-GCM encrypt/decrypt throughput at various message sizes.

CLI:
    python benchmarks/benchmark_throughput.py [--runs 100] [--output benchmarks/results/throughput.json]

Run from ai_secure_comm/.  No project imports are needed — uses `cryptography`
directly so this script is usable independently of the project root.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Message sizes to benchmark (bytes).
SIZES_BYTES: list[int] = [
    64,
    256,
    1_024,
    16 * 1_024,
    256 * 1_024,
    1_024 * 1_024,
    4 * 1_024 * 1_024,
]

_NONCE_SIZE = 12   # bytes — NIST-recommended GCM nonce length
_AAD = b"\x01"    # kind-only AAD, matching the project's production convention


def _human_size(n: int) -> str:
    if n < 1_024:
        return f"{n}B"
    if n < 1_024 * 1_024:
        return f"{n // 1_024}KB"
    return f"{n // (1_024 * 1_024)}MB"


def bench_size(
    key: bytes,
    size_bytes: int,
    max_runs: int,
    time_budget_s: float,
) -> dict:
    """Benchmark one message size and return per-direction timing + throughput."""
    plaintext = os.urandom(size_bytes)
    aead = AESGCM(key)

    enc_times: list[float] = []
    dec_times: list[float] = []

    budget_start = time.perf_counter()
    run = 0
    while run < max_runs and (time.perf_counter() - budget_start) < time_budget_s:
        nonce = os.urandom(_NONCE_SIZE)

        t0 = time.perf_counter()
        ciphertext = aead.encrypt(nonce, plaintext, _AAD)
        t1 = time.perf_counter()
        aead.decrypt(nonce, ciphertext, _AAD)
        t2 = time.perf_counter()

        enc_times.append(t1 - t0)
        dec_times.append(t2 - t1)
        run += 1

    enc_mean_s = statistics.mean(enc_times)
    dec_mean_s = statistics.mean(dec_times)

    # Per-direction throughput in MB/s.
    enc_mbps = (size_bytes / 1e6) / enc_mean_s if enc_mean_s > 0 else 0.0
    dec_mbps = (size_bytes / 1e6) / dec_mean_s if dec_mean_s > 0 else 0.0

    return {
        "size_bytes": size_bytes,
        "size_human": _human_size(size_bytes),
        "runs": run,
        "encrypt_mean_ms": round(enc_mean_s * 1000, 6),
        "decrypt_mean_ms": round(dec_mean_s * 1000, 6),
        "encrypt_throughput_mbps": round(enc_mbps, 2),
        "decrypt_throughput_mbps": round(dec_mbps, 2),
    }


def run_all(
    max_runs: int,
    time_budget_s: float,
    output: str,
) -> dict:
    """Run the full throughput benchmark suite and write results to disk."""
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    key = os.urandom(32)  # fresh random AES-256 key

    print(
        f"\n=== AES-256-GCM Throughput Benchmark ===\n"
        f"  Max {max_runs} runs per size, {time_budget_s}s budget\n"
    )

    results: list[dict] = []
    for size in SIZES_BYTES:
        r = bench_size(key, size, max_runs, time_budget_s)
        results.append(r)
        print(
            f"  {r['size_human']:>6s}: "
            f"enc {r['encrypt_throughput_mbps']:>8.1f} MB/s, "
            f"dec {r['decrypt_throughput_mbps']:>8.1f} MB/s  "
            f"(enc_ms={r['encrypt_mean_ms']:.4f}, "
            f"dec_ms={r['decrypt_mean_ms']:.4f}, runs={r['runs']})"
        )

    output_data = {
        "results": results,
        "system_info": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    output_path.write_text(json.dumps(output_data, indent=2))
    print(f"\nResults written to {output_path}")
    return output_data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark AES-256-GCM throughput for various message sizes."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=100,
        help="Max iterations per size (default: 100). Capped by --time-budget.",
    )
    parser.add_argument(
        "--time-budget",
        type=float,
        default=5.0,
        dest="time_budget",
        help="Per-size time budget in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/results/throughput.json",
        help="Output JSON path (default: benchmarks/results/throughput.json).",
    )
    args = parser.parse_args(argv)
    run_all(max_runs=args.runs, time_budget_s=args.time_budget, output=args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
