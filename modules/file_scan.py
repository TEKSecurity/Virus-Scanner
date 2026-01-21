import hashlib
import os
from typing import Callable, Optional

def hash_file(path: str) -> str | None:
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def scan_directory(
    directory: str,
    bad_hashes: set[str],
    on_progress: Optional[Callable[[int], None]] = None,
) -> list[str]:
    hits: list[str] = []
    scanned = 0

    for root, _, files in os.walk(directory):
        for name in files:
            scanned += 1

            # Update counter immediately and often
            if on_progress and (scanned == 1 or scanned % 10 == 0):
                on_progress(scanned)

            full_path = os.path.join(root, name)
            file_hash = hash_file(full_path)
            if file_hash and file_hash.lower() in bad_hashes:
                hits.append(full_path)

    # final update
    if on_progress:
        on_progress(scanned)

    return hits
