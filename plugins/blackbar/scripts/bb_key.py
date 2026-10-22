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

`local_salt()` is the second local secret: it keys the one-way `hash` operator
and the audit fingerprints, so neither can be reversed by hashing guesses.
$BLACKBAR_SALT wins; otherwise a random salt is generated once at
$XDG_CONFIG_HOME/blackbar/salt and reused. The file is 0600 on POSIX; on
Windows it inherits the folder's permissions. A file that is empty, not hex
or shorter than 16 bytes is replaced.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path


def _config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return Path(base) / "blackbar"


def default_key_file() -> Path:
    env = os.environ.get("BLACKBAR_KEY_FILE")
    if env:
        return Path(env).expanduser()
    return _config_dir() / "key"


def resolve_key(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    env = (os.environ.get("BLACKBAR_KEY") or "").strip()
    if env:
        return env
    kf = default_key_file()
    if kf.is_file():
        try:
            return kf.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None


MIN_SALT_BYTES = 16


def salt_file() -> Path:
    return _config_dir() / "salt"


_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


def _read_salt(path: Path) -> bytes | None:
    """The stored salt; None when missing; b"" when present but unusable."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    # Strict hex, the same rule as the Node server, so both accept the same files.
    salt = bytes.fromhex(text) if _HEX.fullmatch(text) else b""
    if len(salt) < MIN_SALT_BYTES:
        return b""
    if os.name == "posix" and path.stat().st_mode & 0o077:
        os.chmod(path, 0o600)
    return salt


def local_salt() -> bytes:
    env = os.environ.get("BLACKBAR_SALT")
    if env:
        return env.encode("utf-8")
    path = salt_file()
    salt = _read_salt(path)
    if salt:
        return salt
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write a temp file, then put it in place. A missing salt is linked: the
    # first writer wins and a concurrent first use re-reads the winner. An
    # unusable one is replaced atomically.
    tmp = path.with_name(f".salt.{os.getpid()}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(secrets.token_bytes(32).hex())
    try:
        if salt is None:
            os.link(tmp, path)
        else:
            os.replace(tmp, path)
    except FileExistsError:
        pass
    except OSError:  # no hard links on this filesystem
        if not path.exists():
            os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    salt = _read_salt(path)
    if not salt:
        raise OSError(f"cannot create a usable salt at {path}")
    return salt


def known_secrets() -> list[str]:
    """The local secrets as text, to scrub from anything the model sees.

    Never creates the salt file; values shorter than 8 characters are skipped
    (scrubbing them would mangle ordinary text).
    """
    found = [resolve_key(None), os.environ.get("BLACKBAR_SALT"), os.environ.get("PII_AUDIT_SALT")]
    try:
        found.append(salt_file().read_text(encoding="utf-8").strip())
    except OSError:
        pass
    return sorted({v for v in found if v and len(v) >= 8}, key=len, reverse=True)
