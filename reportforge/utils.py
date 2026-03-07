from __future__ import annotations
import os
from pathlib import Path

DEFAULT_HOME = Path.home() / ".reportforge"

def get_home() -> Path:
    env = os.getenv("REPORTFORGE_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return DEFAULT_HOME

def ensure_home() -> Path:
    home = get_home()
    home.mkdir(parents=True, exist_ok=True)
    (home / "exports").mkdir(parents=True, exist_ok=True)
    return home

def get_db_path() -> Path:
    return ensure_home() / "reportforge.db"
