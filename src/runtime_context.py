"""Runtime context paths for assistant-owned notes and findings."""

import os
from pathlib import Path

DEFAULT_CONTEXT_DIR = "runtime-context"


def get_runtime_context_dir() -> Path:
    """Return the configured runtime context directory."""
    return Path(os.getenv("NCA_RUNTIME_CONTEXT_DIR", DEFAULT_CONTEXT_DIR))


def ensure_directory(path: Path) -> Path:
    """Create a data-only directory with non-executable default permissions."""
    path.mkdir(parents=True, exist_ok=True)
    set_private_permissions(path, 0o700)
    return path


def set_private_permissions(path: Path, mode: int) -> bool:
    """
    Best-effort chmod for runtime context paths.

    Runtime context may be a bind mount, synced folder, or externally managed
    notes directory. In those cases chmod can fail even when the path is usable.
    """
    try:
        path.chmod(mode)
    except PermissionError:
        return False
    return True
