"""Benchmark TPM, RSA-2048, and DH-2048 key-exchange performance.

CLI:
    python benchmarks/benchmark_key_exchange.py [--runs 50] [--output benchmarks/results/key_exchange.json]

Run from ai_secure_comm/ so that `import config` resolves correctly.
The script adjusts sys.path automatically so the project root is importable
even when invoked as a plain script rather than a module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

# Ensure ai_secure_comm/ is importable regardless of how the script is invoked.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

import config
from core.sync_protocol import SyncProtocol
from core.tpm import TreeParityMachine


# ---------------------------------------------------------------------------
# TPM benchmark
# ---------------------------------------------------------------------------


def bench_tpm(runs: int) -> dict:
    """Time TPM neural key exchange using LoopbackTransport."""
    times_ms: list[float] = []
    rounds_list: list[int] = []

    for i in range(runs):
        print(f"  [{i + 1:>{len(str(runs))}}/{runs}] tpm runs…", end="\r", flush=True)
        tpm_a = TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L)
        tpm_b = TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L)
        t0 = time.perf_counter()
        result = SyncProtocol(tpm_a, tpm_b).synchronize()
        t1 = time.perf_counter()
        if not result.success:
            # Pathological run — skip so stats aren't distorted by rare failures.
            continue
        times_ms.append((t1 - t0) * 1000.0)
        rounds_list.append(result.rounds)

    print(f"  [{runs}/{runs}] tpm done.          ")

    if not times_ms:
        raise RuntimeError("All TPM runs failed to synchronise — check TPM parameters.")

    return {
        "mean_ms": round(statistics.mean(times_ms), 3),
        "median_ms": round(statistics.median(times_ms), 3),
        "std_ms": round(statistics.stdev(times_ms) if len(times_ms) > 1 else 0.0, 3),
        "min_ms": round(min(times_ms), 3),
        "max_ms": round(max(times_ms), 3),
        "avg_rounds": round(statistics.mean(rounds_list), 1),
        "runs": len(times_ms),
    }


# ---------------------------------------------------------------------------
# RSA-2048 benchmark
# ---------------------------------------------------------------------------


def bench_rsa(runs: int) -> dict:
    """Time RSA-2048 key-pair generation + OAEP encrypt + decrypt of 256-bit key."""
    total_times: list[float] = []
    keygen_times: list[float] = []
    enc_dec_times: list[float] = []

    for i in range(runs):
        print(f"  [{i + 1:>{len(str(runs))}}/{runs}] rsa runs…", end="\r", flush=True)

        t0 = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        t_keygen = time.perf_counter()

        public_key = private_key.public_key()
        session_key = os.urandom(32)  # 256-bit symmetric key

        t_enc_start = time.perf_counter()
        ciphertext = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        t_end = time.perf_counter()

        assert decrypted == session_key, "RSA round-trip mismatch"

        keygen_times.append((t_keygen - t0) * 1000.0)
        enc_dec_times.append((t_end - t_enc_start) * 1000.0)
        total_times.append((t_end - t0) * 1000.0)

    print(f"  [{runs}/{runs}] rsa done.          ")

    return {
        "mean_ms": round(statistics.mean(total_times), 3),
        "median_ms": round(statistics.median(total_times), 3),
        "std_ms": round(statistics.stdev(total_times) if len(total_times) > 1 else 0.0, 3),
        "min_ms": round(min(total_times), 3),
        "max_ms": round(max(total_times), 3),
        "keypair_gen_ms_mean": round(statistics.mean(keygen_times), 3),
        "encrypt_decrypt_ms_mean": round(statistics.mean(enc_dec_times), 3),
        "runs": runs,
    }


# ---------------------------------------------------------------------------
# DH-2048 benchmark
# ---------------------------------------------------------------------------


def bench_dh(runs: int) -> dict:
    """Time DH-2048 key agreement.

    DH parameter generation is slow (~2–4 s) so it is done once before
    the timed loop and reported separately as ``param_gen_ms_one_time``.
    The timed section covers: both sides generate private keys, exchange
    public keys, derive shared secrets, and SHA-256-hash to 256 bits.
    """
    print("  Generating DH-2048 parameters (one-time, may take 2–4 s)…", flush=True)
    t_param_start = time.perf_counter()
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    param_gen_ms = (time.perf_counter() - t_param_start) * 1000.0
    print(f"  DH parameters ready in {param_gen_ms:.0f} ms", flush=True)

    times_ms: list[float] = []

    for i in range(runs):
        print(f"  [{i + 1:>{len(str(runs))}}/{runs}] dh runs…", end="\r", flush=True)

        t0 = time.perf_counter()

        # Both sides generate ephemeral private keys.
        private_key_a = parameters.generate_private_key()
        private_key_b = parameters.generate_private_key()

        # Exchange public keys and derive shared secrets.
        shared_key_a = private_key_a.exchange(private_key_b.public_key())
        shared_key_b = private_key_b.exchange(private_key_a.public_key())

        # Derive 256-bit keys via SHA-256 (same rule on both sides).
        key_a = hashlib.sha256(shared_key_a).digest()
        key_b = hashlib.sha256(shared_key_b).digest()

        t1 = time.perf_counter()

        assert key_a == key_b, "DH shared-secret mismatch"
        times_ms.append((t1 - t0) * 1000.0)

    print(f"  [{runs}/{runs}] dh done.          ")

    return {
        "mean_ms": round(statistics.mean(times_ms), 3),
        "median_ms": round(statistics.median(times_ms), 3),
        "std_ms": round(statistics.stdev(times_ms) if len(times_ms) > 1 else 0.0, 3),
        "min_ms": round(min(times_ms), 3),
        "max_ms": round(max(times_ms), 3),
        "param_gen_ms_one_time": round(param_gen_ms, 1),
        "agreement_ms_mean": round(statistics.mean(times_ms), 3),
        "runs": runs,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def run_all(runs: int, output: str) -> dict:
    """Run all three benchmarks and return the combined result dict."""
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Key-Exchange Benchmark ({runs} runs each) ===\n")

    print("[1/3] TPM Neural Key Exchange")
    tpm_results = bench_tpm(runs)
    print(
        f"      mean={tpm_results['mean_ms']:.1f} ms  "
        f"avg_rounds={tpm_results['avg_rounds']:.0f}"
    )

    print("\n[2/3] RSA-2048")
    rsa_results = bench_rsa(runs)
    print(
        f"      mean={rsa_results['mean_ms']:.1f} ms  "
        f"(keygen={rsa_results['keypair_gen_ms_mean']:.1f} ms, "
        f"enc+dec={rsa_results['encrypt_decrypt_ms_mean']:.1f} ms)"
    )

    print("\n[3/3] Diffie-Hellman 2048-bit")
    dh_results = bench_dh(runs)
    print(
        f"      mean={dh_results['mean_ms']:.1f} ms  "
        f"(param_gen one-time={dh_results['param_gen_ms_one_time']:.0f} ms)"
    )

    result = {
        "tpm": tpm_results,
        "rsa_2048": rsa_results,
        "dh_2048": dh_results,
        "system_info": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    output_path.write_text(json.dumps(result, indent=2))
    print(f"\nResults written to {output_path}")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark TPM, RSA-2048, and DH-2048 key-exchange performance."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=50,
        help="Number of timed iterations per scheme (default: 50).",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/results/key_exchange.json",
        help="Output JSON path (default: benchmarks/results/key_exchange.json).",
    )
    args = parser.parse_args(argv)
    run_all(runs=args.runs, output=args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
