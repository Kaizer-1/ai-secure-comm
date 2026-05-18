"""Core cryptographic modules for the AI-Enhanced Secure Communication System.

Phase 1 contents:
    - tpm: Tree Parity Machine (neural cryptography primitive)
    - sync_protocol: Two-TPM mutual learning orchestrator
    - crypto_engine: AES-256-GCM authenticated-encryption wrapper
"""

from .tpm import TreeParityMachine
from .sync_protocol import SyncProtocol, SyncResult
from .crypto_engine import CryptoEngine

__all__ = [
    "TreeParityMachine",
    "SyncProtocol",
    "SyncResult",
    "CryptoEngine",
]
