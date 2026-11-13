"""Test doubles for the AI layer (no network, no real models)."""

import json

from binproof.ai.models import FunctionAnalysis  # noqa: F401
from binproof.ai.prompts import EXAMPLE_OUTPUT
from binproof.ai.providers.base import HttpResponse, LLMProvider, LLMResponse

GOOD_JSON = json.dumps(EXAMPLE_OUTPUT)


class ScriptedProvider(LLMProvider):
    """Returns scripted items in order: a str, an LLMResponse, or an Exception to raise."""
    name = "fake"

    def __init__(self, script, model="fake-model"):
        super().__init__(model)
        self.script = list(script)
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, str):
            return LLMResponse(text=item, model=self.model, input_tokens=10, output_tokens=5)
        return item


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def post_json(self, url, headers, payload, timeout):
        self.calls.append({"url": url, "headers": dict(headers), "payload": payload, "timeout": timeout})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def http(status, body, headers=None):
    return HttpResponse(status, headers or {}, body if isinstance(body, str) else json.dumps(body))


def anthropic_ok(text=GOOD_JSON, stop="end_turn"):
    return http(200, {"model": "m-1", "stop_reason": stop,
                      "content": [{"type": "text", "text": text}],
                      "usage": {"input_tokens": 11, "output_tokens": 7}})


def openai_ok(text=GOOD_JSON, finish="stop"):
    return http(200, {"model": "m-1", "usage": {"prompt_tokens": 11, "completion_tokens": 7},
                      "choices": [{"finish_reason": finish, "message": {"role": "assistant", "content": text}}]})
