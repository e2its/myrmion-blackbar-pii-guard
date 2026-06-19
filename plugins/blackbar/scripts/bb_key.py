"""
bb_key.py
=========
Shared session-key resolution for blackbar's reversible encryption. The CLI
(`blackbar_cli.py`) and the hooks (`pii_filter.py`) both use this, so a value
encrypted by a PostToolUse hook can be decrypted by the CLI (and vice-versa)
as long as they see the same key.

Resolution order (first match wins):
  1. an explicit key passed by the caller
  2. $BLACKBAR_KEY
  3. the key file at $BLACKBAR_KEY_FILE (default ~/.config/blackbar/key)

Create the default key file once with `blackbar keygen`.
"""

from __future__ import annotations

import os
from pathlib import Path


def default_key_file() -> Path:
    env = os.environ.get("BLACKBAR_KEY_FILE")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return Path(base) / "blackbar" / "key"


def resolve_key(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    env = os.environ.get("BLACKBAR_KEY")
    if env:
        return env
    kf = default_key_file()
    if kf.is_file():
        try:
            return kf.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None
