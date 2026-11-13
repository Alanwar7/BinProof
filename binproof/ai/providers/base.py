"""Provider-neutral types, the provider interface and shared HTTP plumbing."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, Sequence, Tuple

from ..errors import (
    ProviderAuthError, ProviderRateLimitError, ProviderRequestError,
    ProviderResponseError, ProviderUnavailableError,
)


@dataclass(frozen=True)
class Message:
    role: str  # "user" | "assistant"
    content: str


@dataclass(frozen=True)
class LLMRequest:
    system: str
    messages: Tuple[Message, ...]
    max_tokens: int
    temperature: Optional[float] = None  # omitted from the API call when None


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str = ""
    truncated: bool = False  # output was cut off by the token limit
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None


class LLMProvider(ABC):
    """Everything the analysis code knows about a model provider."""

    name: str = "provider"

    def __init__(self, model: str):
        self.model = model

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse:
        """Send one request. Raise a ProviderError subclass on failure."""


# ---- HTTP transport (injectable so providers can be tested without a network) ----

@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]  # lower-cased names
    body: str


class HttpTransport(Protocol):
    def post_json(self, url: str, headers: Mapping[str, str], payload: Dict[str, Any],
                  timeout: float) -> HttpResponse: ...


class UrllibTransport:
    """Default transport: standard library only. Error statuses are returned, not raised."""

    USER_AGENT = "binproof/0.3"

    def post_json(self, url, headers, payload, timeout) -> HttpResponse:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": self.USER_AGENT, **headers})
        host = urllib.parse.urlparse(url).netloc or url
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return HttpResponse(resp.status, _lower(resp.headers.items()),
                                    resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return HttpResponse(exc.code, _lower((exc.headers or {}).items()), body)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ProviderUnavailableError("network error contacting %s: %s" % (host, reason)) from None


def _lower(items) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in items}


# ---- shared response handling -------------------------------------------------------

def redact(text: str, secrets: Sequence[Optional[str]]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def _error_detail(body: str) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return body.strip()[:300]
    if isinstance(data, dict):
        err = data.get("error", data)
        if isinstance(err, dict):
            return str(err.get("message") or err.get("type") or "")[:300]
        if isinstance(err, str):
            return err[:300]
        if data.get("message"):
            return str(data["message"])[:300]
    return ""


def _retry_after(headers: Mapping[str, str]) -> Optional[float]:
    raw = headers.get("retry-after")
    try:
        return max(0.0, float(raw)) if raw is not None else None
    except ValueError:
        return None  # HTTP-date form: ignore, backoff will be used


def raise_for_status(provider: str, resp: HttpResponse, secrets: Sequence[Optional[str]] = ()) -> None:
    """Map an HTTP error status to a typed ProviderError (never includes secrets)."""
    if 200 <= resp.status < 300:
        return
    detail = redact(_error_detail(resp.body), secrets)
    head = "%s API error (HTTP %d)" % (provider, resp.status)
    suffix = ": %s" % detail if detail else ""
    if resp.status in (401, 403):
        raise ProviderAuthError("%s: authentication or permission failed; check the API key%s"
                                % (head, suffix))
    if resp.status == 429:
        raise ProviderRateLimitError("%s: rate limited%s" % (head, suffix), _retry_after(resp.headers))
    if resp.status >= 500 or resp.status == 408:
        raise ProviderUnavailableError("%s: service unavailable%s" % (head, suffix))
    raise ProviderRequestError("%s: request rejected%s" % (head, suffix))


def parse_json_body(provider: str, resp: HttpResponse) -> Dict[str, Any]:
    try:
        data = json.loads(resp.body)
    except ValueError:
        raise ProviderResponseError("%s returned a body that is not valid JSON" % provider) from None
    if not isinstance(data, dict):
        raise ProviderResponseError("%s returned an unexpected response shape" % provider)
    return data


def optional_int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
