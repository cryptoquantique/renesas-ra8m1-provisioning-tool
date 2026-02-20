"""
Key cache utilities for storing key metadata locally.

This module provides functions to cache key information (IDs, types, labels)
for quick access without querying the HSM/KMS every time.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from utils.logging import get_logger

logger = get_logger(__name__)

# Default cache file location
DEFAULT_CACHE_DIR = Path.home() / ".provisioning_tool"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "key_cache.json"


def _get_cache_path() -> Path:
    """Get the cache file path, creating directory if needed."""
    cache_dir = DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)
    return DEFAULT_CACHE_FILE


def load_cache() -> Dict[str, Any]:
    """
    Load the entire key cache from disk.

    Returns:
        Dictionary containing cached key data
    """
    cache_path = _get_cache_path()

    if not cache_path.exists():
        return {"keys": {}, "last_updated": None}

    try:
        with open(cache_path, "r") as f:
            data = json.load(f)
            return data
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load key cache: {e}")
        return {"keys": {}, "last_updated": None}


def _save_cache(cache_data: Dict[str, Any]) -> None:
    """
    Save cache data to disk.

    Args:
        cache_data: Cache dictionary to save
    """
    cache_path = _get_cache_path()
    cache_data["last_updated"] = datetime.now().isoformat()

    try:
        with open(cache_path, "w") as f:
            json.dump(cache_data, f, indent=2)
    except IOError as e:
        logger.error(f"Failed to save key cache: {e}")


def save_key_to_cache(
    key_id: str,
    key_type: str,
    curve: str,
    label: Optional[str] = None,
    **extra_metadata
) -> None:
    """
    Save a key's metadata to the local cache.

    Args:
        key_id: Key identifier (ARN, ID, or handle)
        key_type: Key type (e.g., "CUSTOMER", "OEM_ROOT")
        curve: Key curve (e.g., "SECP256R1")
        label: Optional key label/alias
        **extra_metadata: Additional metadata to store
    """
    cache = load_cache()

    cache["keys"][key_id] = {
        "key_id": key_id,
        "key_type": key_type,
        "curve": curve,
        "label": label,
        "created_at": datetime.now().isoformat(),
        **extra_metadata
    }

    _save_cache(cache)
    logger.debug(f"Saved key {key_id} to cache")


def get_cached_keys() -> List[Dict[str, Any]]:
    """
    Get list of all cached keys.

    Returns:
        List of key metadata dictionaries
    """
    cache = load_cache()
    return list(cache.get("keys", {}).values())


def get_cached_key(key_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a specific key's cached metadata.

    Args:
        key_id: Key identifier

    Returns:
        Key metadata dictionary or None if not found
    """
    cache = load_cache()
    return cache.get("keys", {}).get(key_id)


def remove_key_from_cache(key_id: str) -> bool:
    """
    Remove a key from the cache.

    Args:
        key_id: Key identifier to remove

    Returns:
        True if key was removed, False if not found
    """
    cache = load_cache()

    if key_id in cache.get("keys", {}):
        del cache["keys"][key_id]
        _save_cache(cache)
        logger.debug(f"Removed key {key_id} from cache")
        return True

    return False


def clear_cache() -> None:
    """Clear all cached keys."""
    _save_cache({"keys": {}, "last_updated": None})
    logger.info("Key cache cleared")


def update_key_in_cache(key_id: str, **updates) -> bool:
    """
    Update a cached key's metadata.

    Args:
        key_id: Key identifier
        **updates: Fields to update

    Returns:
        True if key was updated, False if not found
    """
    cache = load_cache()

    if key_id in cache.get("keys", {}):
        cache["keys"][key_id].update(updates)
        cache["keys"][key_id]["updated_at"] = datetime.now().isoformat()
        _save_cache(cache)
        return True

    return False
