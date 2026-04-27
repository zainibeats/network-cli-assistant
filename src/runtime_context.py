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
    path.chmod(0o700)
    return path
