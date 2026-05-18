"""Phase 1 end-to-end demo.

Run with:  python demo_phase1.py

Steps:
    1. Build two TreeParityMachines with *different* secret weights.
    2. Synchronise them via mutual learning (in-process; same RNG seed
       stands in for the public input feed Phase 2 will exchange over
       the network).
    3. Derive an AES-256 key from the synchronised weights on each side.
    4. Encrypt a sample message on side A; decrypt on side B.
    5. Demonstrate that tampering with the ciphertext is detected.

The point of this script is to prove the full Phase 1 stack works
end to end before any networking, UI, or IDS code is added.
"""

from __future__ import annotations

import logging
import sys

import numpy as np
from cryptography.exceptions import InvalidTag

import config
from core.crypto_engine import CryptoEngine
from core.sync_protocol import SyncProtocol
from core.tpm import TreeParityMachine


def _banner(title: str) -> None:
    line = "=" * 60
    print(f"\n{line}\n{title}\n{line}")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    _banner("1. Build two TPMs with DIFFERENT random secret weights")
    rng_a = np.random.default_rng(seed=config.DEMO_SEED)
    rng_b = np.random.default_rng(seed=config.DEMO_SEED + 1)
    tpm_a = TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L, rng=rng_a)
    tpm_b = TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L, rng=rng_b)
    print(f"  {config.ROLE_A}: {tpm_a}")
    print(f"  {config.ROLE_B}: {tpm_b}")
    assert tpm_a.weight_fingerprint() != tpm_b.weight_fingerprint(), \
        "demo precondition: TPMs should start with different weights"

    _banner("2. Synchronise them through mutual learning")
    proto = SyncProtocol(
        tpm_a, tpm_b,
        learning_rule=config.TPM_DEFAULT_LEARNING_RULE,
        seed=config.DEMO_SEED + 2,
    )
    result = proto.synchronize()
    print(f"  success         : {result.success}")
    print(f"  rounds          : {result.rounds}")
    print(f"  elapsed (s)     : {result.elapsed_seconds:.4f}")
    print(f"  fingerprint     : {result.final_fingerprint}")
    if not result.success:
        print("FAILED: TPMs did not synchronise within the round budget.")
        return 1
    assert tpm_a.weight_fingerprint() == tpm_b.weight_fingerprint()

    _banner("3. Derive AES-256 keys on each side")
    key_a = CryptoEngine.derive_key_from_tpm(tpm_a.export_weights())
    key_b = CryptoEngine.derive_key_from_tpm(tpm_b.export_weights())
    print(f"  {config.ROLE_A} key: {key_a.hex()}")
    print(f"  {config.ROLE_B} key: {key_b.hex()}")
    assert key_a == key_b, "derived keys must be identical after sync"

    _banner("4. Encrypt on A, decrypt on B")
    engine_a = CryptoEngine(key_a)
    engine_b = CryptoEngine(key_b)
    plaintext = (
        b"Hello from device A. "
        b"This message was encrypted with a key never sent over the wire."
    )
    bundle = engine_a.encrypt(plaintext, associated_data=b"phase-1-demo")
    print(f"  plaintext       : {plaintext!r}")
    print(f"  bundle length   : {len(bundle)} bytes "
          f"(nonce {config.AES_NONCE_BYTES} + ct {len(plaintext)} "
          f"+ tag {config.AES_TAG_BYTES})")
    decrypted = engine_b.decrypt(bundle, associated_data=b"phase-1-demo")
    print(f"  decrypted on B  : {decrypted!r}")
    assert decrypted == plaintext

    _banner("5. Show that tampering is detected")
    tampered = bytearray(bundle)
    tampered[config.AES_NONCE_BYTES + 5] ^= 0x01  # flip a bit in the ciphertext
    try:
        engine_b.decrypt(bytes(tampered), associated_data=b"phase-1-demo")
    except InvalidTag:
        print("  Tampered ciphertext correctly rejected with InvalidTag.")
    else:
        print("FAILED: tampering was NOT detected.")
        return 1

    _banner("Phase 1 demo finished successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
