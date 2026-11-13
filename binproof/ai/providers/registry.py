"""Provider registry: name -> factory.

To add a provider, implement LLMProvider and call register_provider(...).
Nothing outside this package needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from ..errors import ConfigError
from .anthropic import AnthropicProvider
from .base import HttpTransport, LLMProvider
from .openai_compat import OpenAICompatProvider

if TYPE_CHECKING:  # pragma: no cover
    from ..config import AIConfig

Factory = Callable[["AIConfig", Optional[HttpTransport]], LLMProvider]


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    factory: Factory
    api_key_env: Optional[str] = None   # conventional env var for this provider's key
    requires_key: bool = True
    requires_base_url: bool = False
    description: str = ""


_SPECS: Dict[str, ProviderSpec] = {}


def register_provider(spec: ProviderSpec, *, replace: bool = False) -> None:
    key = spec.name.lower()
    if key in _SPECS and not replace:
        raise ValueError("provider %r is already registered" % key)
    _SPECS[key] = spec


def available_providers() -> List[str]:
    return sorted(_SPECS)


def get_spec(name: str) -> ProviderSpec:
    spec = _SPECS.get((name or "").lower())
    if spec is None:
        raise ConfigError("unknown provider %r (available: %s)" % (name, ", ".join(available_providers())))
    return spec


def create_provider(config: "AIConfig", transport: Optional[HttpTransport] = None) -> LLMProvider:
    return get_spec(config.provider).factory(config, transport)


# ---- built-in providers ---------------------------------------------------------

def _anthropic(cfg, transport):
    return AnthropicProvider(cfg.model, cfg.api_key, base_url=cfg.base_url,
                             timeout=cfg.timeout, transport=transport)


def _openai(cfg, transport):
    return OpenAICompatProvider(cfg.model, cfg.base_url or "https://api.openai.com/v1",
                                api_key=cfg.api_key, max_tokens_field="max_completion_tokens",
                                timeout=cfg.timeout, transport=transport, name="openai")


def _ollama(cfg, transport):
    return OpenAICompatProvider(cfg.model, cfg.base_url or "http://localhost:11434/v1",
                                api_key=cfg.api_key, timeout=cfg.timeout,
                                transport=transport, name="ollama")


def _generic(cfg, transport):
    return OpenAICompatProvider(cfg.model, cfg.base_url, api_key=cfg.api_key,
                                timeout=cfg.timeout, transport=transport)


for _spec in (
    ProviderSpec("anthropic", _anthropic, "ANTHROPIC_API_KEY", True, False, "Anthropic Messages API"),
    ProviderSpec("openai", _openai, "OPENAI_API_KEY", True, False, "OpenAI chat completions"),
    ProviderSpec("ollama", _ollama, None, False, False, "local Ollama server (OpenAI-compatible endpoint)"),
    ProviderSpec("openai-compatible", _generic, None, False, True,
                 "any OpenAI-compatible server; set BINPROOF_BASE_URL"),
):
    register_provider(_spec)
