"""AI configuration from the environment (and CLI overrides). Secrets stay out of code.

    BINPROOF_PROVIDER      anthropic | openai | ollama | openai-compatible
    BINPROOF_MODEL         model name (no default: defaults go stale)
    BINPROOF_API_KEY       API key; else ANTHROPIC_API_KEY / OPENAI_API_KEY by provider
    BINPROOF_BASE_URL      override the API endpoint (required for openai-compatible)
    BINPROOF_TIMEOUT       seconds per request (default 120)
    BINPROOF_MAX_TOKENS    output token limit (default 4096)
    BINPROOF_TEMPERATURE   optional; omitted from requests when unset
    BINPROOF_MAX_ATTEMPTS  tries per request on rate limits/outages (default 4)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, TypeVar

from .errors import ConfigError
from .providers.registry import available_providers, get_spec

T = TypeVar("T")


@dataclass(frozen=True)
class AIConfig:
    provider: str
    model: str
    api_key: Optional[str] = field(default=None, repr=False)  # never printed
    base_url: Optional[str] = None
    timeout: float = 120.0
    max_tokens: int = 4096
    temperature: Optional[float] = None
    max_attempts: int = 4

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **overrides) -> "AIConfig":
        """Build a config; keyword overrides (e.g. from CLI flags) win over the environment."""
        env = os.environ if env is None else env

        def pick(key: str, override_name: str) -> Optional[str]:
            value = overrides.get(override_name)
            if value is None:
                value = env.get(key)
            if value is not None and not isinstance(value, str):
                value = str(value)  # numeric CLI overrides
            return value.strip() if value and value.strip() else None

        def number(raw: Optional[str], kind: Callable[[str], T], default: Optional[T], label: str):
            if raw is None:
                return default
            try:
                return kind(raw)
            except ValueError:
                raise ConfigError("%s must be a number, got %r" % (label, raw)) from None

        provider = pick("BINPROOF_PROVIDER", "provider")
        if not provider:
            raise ConfigError("no provider configured: set BINPROOF_PROVIDER or pass --provider "
                              "(available: %s)" % ", ".join(available_providers()))
        spec = get_spec(provider)

        model = pick("BINPROOF_MODEL", "model")
        if not model:
            raise ConfigError("no model configured: set BINPROOF_MODEL or pass --model")

        api_key = pick("BINPROOF_API_KEY", "api_key")
        if api_key is None and spec.api_key_env:
            api_key = (env.get(spec.api_key_env) or "").strip() or None
        if spec.requires_key and not api_key:
            names = " or ".join(n for n in ("BINPROOF_API_KEY", spec.api_key_env) if n)
            raise ConfigError("provider %r needs an API key: set %s" % (spec.name, names))

        base_url = pick("BINPROOF_BASE_URL", "base_url")
        if spec.requires_base_url and not base_url:
            raise ConfigError("provider %r needs BINPROOF_BASE_URL (or --base-url)" % spec.name)

        max_tokens = number(pick("BINPROOF_MAX_TOKENS", "max_tokens"), int, 4096, "BINPROOF_MAX_TOKENS")
        attempts = number(pick("BINPROOF_MAX_ATTEMPTS", "max_attempts"), int, 4, "BINPROOF_MAX_ATTEMPTS")
        if max_tokens < 1 or attempts < 1:
            raise ConfigError("max tokens and max attempts must be at least 1")
        return cls(
            provider=spec.name, model=model, api_key=api_key, base_url=base_url,
            timeout=number(pick("BINPROOF_TIMEOUT", "timeout"), float, 120.0, "BINPROOF_TIMEOUT"),
            max_tokens=max_tokens,
            temperature=number(pick("BINPROOF_TEMPERATURE", "temperature"), float, None,
                               "BINPROOF_TEMPERATURE"),
            max_attempts=attempts,
        )
