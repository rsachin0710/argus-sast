"""API key storage. Keys are never written to config.toml or to reports.

Lookup order for a provider's key:
    1. environment variable (ANTHROPIC_API_KEY / OPENAI_API_KEY / XAI_API_KEY)
    2. the OS keyring (macOS Keychain, Windows Credential Manager, Secret Service)
    3. fallback file ~/.config/argus/credentials.toml with 0600 permissions,
       used only when no keyring backend is available (e.g. headless Linux CI)

Ollama runs locally and needs no key.
"""

from __future__ import annotations

import os
from pathlib import Path

from .config import ProviderName, config_dir

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ENV_VARS = {
    ProviderName.ANTHROPIC: "ANTHROPIC_API_KEY",
    ProviderName.OPENAI: "OPENAI_API_KEY",
    ProviderName.XAI: "XAI_API_KEY",
}
_SERVICE = "argus-sast"


def _keyring():
    """Return a usable keyring module, or None (missing / fail backend)."""
    if os.environ.get("ARGUS_DISABLE_KEYRING"):
        return None
    try:
        import keyring
        from keyring.backends import fail

        if isinstance(keyring.get_keyring(), fail.Keyring):
            return None
        return keyring
    except Exception:
        return None


def _fallback_file() -> Path:
    return config_dir() / "credentials.toml"


def get_api_key(provider: ProviderName) -> str | None:
    if provider == ProviderName.OLLAMA:
        return None
    env = os.environ.get(ENV_VARS[provider])
    if env:
        return env.strip()
    kr = _keyring()
    if kr is not None:
        try:
            value = kr.get_password(_SERVICE, provider.value)
            if value:
                return value
        except Exception:
            pass
    path = _fallback_file()
    if path.is_file():
        with path.open("rb") as fh:
            return tomllib.load(fh).get(provider.value) or None
    return None


def set_api_key(provider: ProviderName, key: str) -> str:
    """Store a key; returns where it went ("keyring" or the fallback path)."""
    if provider == ProviderName.OLLAMA:
        raise ValueError("Ollama does not use an API key")
    key = key.strip()
    if not key:
        raise ValueError("empty API key")
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(_SERVICE, provider.value, key)
            return "OS keyring"
        except Exception:
            pass
    path = _fallback_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if path.is_file():
        with path.open("rb") as fh:
            existing = tomllib.load(fh)
    existing[provider.value] = key
    body = "\n".join(f'{k} = "{v}"' for k, v in existing.items()) + "\n"
    # Create with restrictive permissions before writing the secret.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    return str(path)


def key_status(provider: ProviderName) -> str:
    """Human-readable status that never reveals the key itself."""
    if provider == ProviderName.OLLAMA:
        return "not needed"
    if os.environ.get(ENV_VARS[provider]):
        return f"set (env {ENV_VARS[provider]})"
    return "set" if get_api_key(provider) else "not set"
