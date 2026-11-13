"""Errors for the AI layer. All derive from BinProofError, so the CLI's existing
`except BinProofError` handler covers them."""

from __future__ import annotations

from typing import Optional

from ..errors import BinProofError


class AIError(BinProofError):
    """Base class for AI-layer failures."""


class ConfigError(AIError):
    """Missing or invalid AI configuration (provider, model, API key...)."""


# ---- provider failures ----------------------------------------------------

class ProviderError(AIError):
    """The model provider could not complete the request."""


class ProviderAuthError(ProviderError):
    """Authentication or permission failure (bad/missing API key)."""


class ProviderRateLimitError(ProviderError):
    """Rate limited. `retry_after` is the provider's hint in seconds, if given."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class ProviderUnavailableError(ProviderError):
    """Network failure, timeout or a 5xx/overloaded response (usually transient)."""


class ProviderRequestError(ProviderError):
    """The provider rejected the request (bad model name, input too long...)."""


class ProviderResponseError(ProviderError):
    """The provider answered, but not in a usable shape (empty, refusal, bad JSON envelope)."""


# ---- model output / context ---------------------------------------------------

class MalformedAIResponseError(AIError):
    """The model's text could not be parsed into the required schema."""

    def __init__(self, message: str, raw_response: str = "", truncated: bool = False):
        super().__init__(message)
        self.problem = message
        self.raw_response = raw_response
        self.truncated = truncated


class ContextError(AIError):
    """The function context could not be built."""


class InsufficientContextError(ContextError):
    """There is no code (decompiled or assembly) to analyze for this function."""
