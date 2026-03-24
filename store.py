"""Persistent key-value store with optional Fernet encryption at rest.

Uses FileTreeStore from py-key-value-aio (bundled with FastMCP 3.0).
When STORAGE_ENCRYPTION_KEY is set, values are encrypted on disk.
Without it, values are stored as plaintext JSON (useful for local dev).

Data directory defaults to /data/kv but can be overridden via DATA_DIR.

NOTE: Filenames on disk are the raw store keys (e.g. MCP access tokens).
FernetEncryptionWrapper encrypts values but not filenames. This is an
accepted trade-off — an attacker with filesystem access can enumerate
active tokens but cannot read their contents without the encryption
key, and filesystem access typically implies full compromise anyway.
"""

import asyncio
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet
from key_value.aio.stores.filetree import FileTreeStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

logger = logging.getLogger("scoutbook.store")

_DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")) / "kv"

_store = None
_store_lock = asyncio.Lock()


async def get_store():
    """Return the initialized store singleton (async — calls setup on first use)."""
    global _store
    if _store is not None:
        return _store

    async with _store_lock:
        # Double-check after acquiring lock
        if _store is not None:
            return _store

        _DATA_DIR.mkdir(parents=True, exist_ok=True)

        base = FileTreeStore(data_directory=_DATA_DIR)
        await base.setup()

        encryption_key = os.environ.get("STORAGE_ENCRYPTION_KEY")
        if encryption_key:
            _store = FernetEncryptionWrapper(
                key_value=base,
                fernet=Fernet(encryption_key.encode()),
            )
            logger.info("Persistent store initialized with encryption at %s", _DATA_DIR)
        else:
            _store = base
            logger.warning(
                "Persistent store initialized WITHOUT encryption at %s "
                "(set STORAGE_ENCRYPTION_KEY to encrypt tokens at rest)",
                _DATA_DIR,
            )

        return _store


async def load_collection(collection: str) -> list[tuple[str, dict]]:
    """Load all live entries from a collection as (key, value) pairs.

    Scans the filesystem for stored entries. Expired entries (past TTL)
    are automatically filtered out by the store's get() method.
    """
    store = await get_store()
    collection_dir = _DATA_DIR / collection
    if not collection_dir.is_dir():
        return []

    results = []
    for path in collection_dir.glob("*.json"):
        key = path.stem
        if key.endswith("-info"):
            continue
        val = await store.get(key, collection=collection)
        if val is not None:
            results.append((key, val))

    return results
