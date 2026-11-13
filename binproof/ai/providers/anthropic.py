"""Anthropic Messages API provider (standard library HTTP only)."""

from __future__ import annotations

from typing import Optional

from ..errors import ProviderResponseError
from .base import (
    HttpTransport, LLMProvider, LLMRequest, LLMResponse, UrllibTransport,
    optional_int, parse_json_body, raise_for_status,
)

DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str, api_key: str, *, base_url: Optional[str] = None,
                 timeout: float = 120.0, transport: Optional[HttpTransport] = None):
        super().__init__(model)
        self._api_key = api_key
        self._url = (base_url or DEFAULT_BASE_URL).rstrip("/") + "/v1/messages"
        self._timeout = timeout
        self._transport = transport or UrllibTransport()

    def complete(self, request: LLMRequest) -> LLMResponse:
        payload = {
            "model": self.model,
            "max_tokens": request.max_tokens,
            "system": request.system,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        headers = {"x-api-key": self._api_key, "anthropic-version": API_VERSION}

        resp = self._transport.post_json(self._url, headers, payload, self._timeout)
        raise_for_status(self.name, resp, [self._api_key])
        data = parse_json_body(self.name, resp)

        stop = data.get("stop_reason")
        if stop == "refusal":
            raise ProviderResponseError("anthropic: the model declined to answer this request")
        blocks = data.get("content")
        if not isinstance(blocks, list):
            raise ProviderResponseError("anthropic: response has no content list")
        text = "".join(b.get("text", "") for b in blocks
                       if isinstance(b, dict) and b.get("type") == "text"
                       and isinstance(b.get("text"), str))
        if not text.strip():
            raise ProviderResponseError("anthropic: response contained no text (stop_reason=%s)" % stop)
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return LLMResponse(
            text=text, model=str(data.get("model") or self.model),
            truncated=(stop == "max_tokens"),
            input_tokens=optional_int(usage.get("input_tokens")),
            output_tokens=optional_int(usage.get("output_tokens")))
