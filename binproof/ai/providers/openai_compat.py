"""OpenAI-style chat completions provider.

Covers OpenAI itself and any server that speaks the same protocol (Ollama,
LM Studio, vLLM, llama.cpp server...). Which token-limit field to send differs
between them, so it is configurable.
"""

from __future__ import annotations

from typing import Optional

from ..errors import ProviderResponseError
from .base import (
    HttpTransport, LLMProvider, LLMRequest, LLMResponse, UrllibTransport,
    optional_int, parse_json_body, raise_for_status,
)


class OpenAICompatProvider(LLMProvider):
    name = "openai-compatible"

    def __init__(self, model: str, base_url: str, *, api_key: Optional[str] = None,
                 max_tokens_field: str = "max_tokens", timeout: float = 120.0,
                 transport: Optional[HttpTransport] = None, name: Optional[str] = None):
        super().__init__(model)
        if name:
            self.name = name
        self._api_key = api_key
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._max_tokens_field = max_tokens_field
        self._timeout = timeout
        self._transport = transport or UrllibTransport()

    def complete(self, request: LLMRequest) -> LLMResponse:
        messages = [{"role": "system", "content": request.system}]
        messages += [{"role": m.role, "content": m.content} for m in request.messages]
        payload = {"model": self.model, "messages": messages,
                   self._max_tokens_field: request.max_tokens}
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        headers = {"Authorization": "Bearer %s" % self._api_key} if self._api_key else {}

        resp = self._transport.post_json(self._url, headers, payload, self._timeout)
        raise_for_status(self.name, resp, [self._api_key])
        data = parse_json_body(self.name, resp)

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderResponseError("%s: response has no choices" % self.name)
        choice = choices[0]
        finish = choice.get("finish_reason")
        if finish == "content_filter":
            raise ProviderResponseError("%s: the response was blocked by a content filter" % self.name)
        message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
        text = message.get("content")
        if not isinstance(text, str) or not text.strip():
            raise ProviderResponseError("%s: response contained no text (finish_reason=%s)"
                                        % (self.name, finish))
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return LLMResponse(
            text=text, model=str(data.get("model") or self.model),
            truncated=(finish == "length"),
            input_tokens=optional_int(usage.get("prompt_tokens")),
            output_tokens=optional_int(usage.get("completion_tokens")))
