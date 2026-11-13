import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from binproof.ai.config import AIConfig
from binproof.ai.errors import (
    ConfigError, ProviderAuthError, ProviderRateLimitError, ProviderRequestError,
    ProviderResponseError, ProviderUnavailableError,
)
from binproof.ai.providers import LLMRequest, Message, ProviderSpec, create_provider, register_provider
from binproof.ai.providers.anthropic import AnthropicProvider
from binproof.ai.providers.base import UrllibTransport
from binproof.ai.providers.openai_compat import OpenAICompatProvider
from binproof.ai.retry import RetryPolicy, call_with_retries
from fakes import FakeTransport, anthropic_ok, http, openai_ok

REQ = LLMRequest("sys", (Message("user", "hi"),), 123)


# ---- config ---------------------------------------------------------------------------

def test_config_requires_provider_model_key():
    with pytest.raises(ConfigError, match="BINPROOF_PROVIDER"):
        AIConfig.from_env({})
    with pytest.raises(ConfigError, match="BINPROOF_MODEL"):
        AIConfig.from_env({"BINPROOF_PROVIDER": "anthropic"})
    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        AIConfig.from_env({"BINPROOF_PROVIDER": "anthropic", "BINPROOF_MODEL": "m"})
    with pytest.raises(ConfigError, match="unknown provider"):
        AIConfig.from_env({"BINPROOF_PROVIDER": "nope", "BINPROOF_MODEL": "m"})


def test_config_key_sources_and_secrecy():
    env = {"BINPROOF_PROVIDER": "anthropic", "BINPROOF_MODEL": "m", "ANTHROPIC_API_KEY": "sk-provider"}
    assert AIConfig.from_env(env).api_key == "sk-provider"
    assert AIConfig.from_env({**env, "BINPROOF_API_KEY": "sk-override"}).api_key == "sk-override"
    cfg = AIConfig.from_env(env)
    assert "sk-provider" not in repr(cfg) and "sk-provider" not in str(cfg)


def test_config_local_providers_and_overrides():
    cfg = AIConfig.from_env({"BINPROOF_PROVIDER": "ollama", "BINPROOF_MODEL": "llama"}, max_tokens=2048)
    assert cfg.api_key is None and cfg.max_tokens == 2048 and cfg.temperature is None
    with pytest.raises(ConfigError, match="BASE_URL"):
        AIConfig.from_env({"BINPROOF_PROVIDER": "openai-compatible", "BINPROOF_MODEL": "m"})
    cfg = AIConfig.from_env({"BINPROOF_PROVIDER": "OpenAI-Compatible", "BINPROOF_MODEL": "m",
                             "BINPROOF_BASE_URL": "http://x/v1", "BINPROOF_TEMPERATURE": "0.2"})
    assert cfg.provider == "openai-compatible" and cfg.temperature == 0.2
    with pytest.raises(ConfigError, match="must be a number"):
        AIConfig.from_env({"BINPROOF_PROVIDER": "ollama", "BINPROOF_MODEL": "m", "BINPROOF_TIMEOUT": "abc"})


def test_registry_creates_builtin_and_rejects_duplicates():
    t = FakeTransport()
    for name, extra in (("anthropic", {"BINPROOF_API_KEY": "k"}), ("openai", {"BINPROOF_API_KEY": "k"}),
                        ("ollama", {}), ("openai-compatible", {"BINPROOF_BASE_URL": "http://h/v1"})):
        cfg = AIConfig.from_env({"BINPROOF_PROVIDER": name, "BINPROOF_MODEL": "m", **extra})
        assert create_provider(cfg, t).name == name
    with pytest.raises(ValueError):
        register_provider(ProviderSpec("anthropic", lambda c, t: None))


# ---- anthropic ----------------------------------------------------------------------------

def test_anthropic_request_and_response():
    t = FakeTransport(anthropic_ok("hello"))
    p = AnthropicProvider("model-x", "sk-secret", transport=t)
    r = p.complete(REQ)
    call = t.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "sk-secret" and "anthropic-version" in call["headers"]
    assert call["payload"] == {"model": "model-x", "max_tokens": 123, "system": "sys",
                               "messages": [{"role": "user", "content": "hi"}]}  # no temperature unless set
    assert (r.text, r.truncated, r.input_tokens, r.output_tokens) == ("hello", False, 11, 7)


def test_anthropic_temperature_and_truncation():
    t = FakeTransport(anthropic_ok("{", stop="max_tokens"))
    r = AnthropicProvider("m", "k", transport=t).complete(LLMRequest("s", (Message("user", "x"),), 5, 0.0))
    assert t.calls[0]["payload"]["temperature"] == 0.0 and r.truncated


@pytest.mark.parametrize("status,exc", [(401, ProviderAuthError), (403, ProviderAuthError),
                                        (429, ProviderRateLimitError), (500, ProviderUnavailableError),
                                        (529, ProviderUnavailableError), (400, ProviderRequestError),
                                        (404, ProviderRequestError)])
def test_status_mapping(status, exc):
    t = FakeTransport(http(status, {"error": {"message": "nope"}}))
    with pytest.raises(exc):
        AnthropicProvider("m", "k", transport=t).complete(REQ)


def test_rate_limit_carries_retry_after():
    t = FakeTransport(http(429, {"error": {"message": "slow"}}, {"retry-after": "7"}))
    with pytest.raises(ProviderRateLimitError) as ei:
        AnthropicProvider("m", "k", transport=t).complete(REQ)
    assert ei.value.retry_after == 7.0


def test_api_key_is_redacted_from_errors():
    t = FakeTransport(http(401, {"error": {"message": "invalid key sk-secret-123"}}))
    with pytest.raises(ProviderAuthError) as ei:
        AnthropicProvider("m", "sk-secret-123", transport=t).complete(REQ)
    assert "sk-secret-123" not in str(ei.value) and "***" in str(ei.value)


@pytest.mark.parametrize("resp", [
    http(200, "not json"), http(200, "[1]"), http(200, {"content": "x"}),
    http(200, {"content": [], "stop_reason": "end_turn"}),
    http(200, {"content": [{"type": "text", "text": "x"}], "stop_reason": "refusal"}),
])
def test_anthropic_bad_envelopes(resp):
    with pytest.raises(ProviderResponseError):
        AnthropicProvider("m", "k", transport=FakeTransport(resp)).complete(REQ)


def test_network_error_passes_through():
    t = FakeTransport(ProviderUnavailableError("network error"))
    with pytest.raises(ProviderUnavailableError):
        AnthropicProvider("m", "k", transport=t).complete(REQ)


# ---- openai-compatible ------------------------------------------------------------------------

def test_openai_compat_request_shapes():
    t = FakeTransport(openai_ok("hi"), openai_ok("hi"))
    local = OpenAICompatProvider("llama", "http://localhost:11434/v1/", transport=t)
    r = local.complete(REQ)
    c = t.calls[0]
    assert c["url"] == "http://localhost:11434/v1/chat/completions"
    assert "Authorization" not in c["headers"]
    assert c["payload"]["max_tokens"] == 123 and c["payload"]["messages"][0] == {"role": "system", "content": "sys"}
    assert (r.text, r.input_tokens, r.output_tokens) == ("hi", 11, 7)
    hosted = create_provider(AIConfig.from_env({"BINPROOF_PROVIDER": "openai", "BINPROOF_MODEL": "m",
                                                "BINPROOF_API_KEY": "sk-1"}), t)
    hosted.complete(REQ)
    c = t.calls[1]
    assert c["headers"]["Authorization"] == "Bearer sk-1" and "max_completion_tokens" in c["payload"]
    assert "max_tokens" not in c["payload"]


@pytest.mark.parametrize("resp", [
    http(200, {"choices": []}), http(200, {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]}),
    http(200, {"choices": [{"message": {"content": "x"}, "finish_reason": "content_filter"}]}),
])
def test_openai_bad_envelopes(resp):
    with pytest.raises(ProviderResponseError):
        OpenAICompatProvider("m", "http://h/v1", transport=FakeTransport(resp)).complete(REQ)


def test_openai_length_is_truncation():
    r = OpenAICompatProvider("m", "http://h/v1", transport=FakeTransport(openai_ok("{", "length"))).complete(REQ)
    assert r.truncated


# ---- retry policy ---------------------------------------------------------------------------------

def _flaky(errors, result="ok"):
    items = list(errors)

    def fn():
        if items:
            raise items.pop(0)
        return result
    return fn


def test_retry_backoff_and_retry_after():
    sleeps = []
    pol = RetryPolicy(max_attempts=4, base_delay=2, max_delay=60, jitter=0)
    fn = _flaky([ProviderUnavailableError("a"), ProviderRateLimitError("b", 5.0), ProviderUnavailableError("c")])
    assert call_with_retries(fn, pol, sleep=sleeps.append) == "ok"
    assert sleeps == [2, 5.0, 8]


def test_retry_gives_up_and_skips_fatal_errors():
    sleeps = []
    pol = RetryPolicy(max_attempts=2, jitter=0)
    with pytest.raises(ProviderUnavailableError):
        call_with_retries(_flaky([ProviderUnavailableError("a")] * 5), pol, sleep=sleeps.append)
    assert len(sleeps) == 1
    for fatal in (ProviderAuthError("x"), ProviderRequestError("x")):
        sleeps.clear()
        with pytest.raises(type(fatal)):
            call_with_retries(_flaky([fatal]), pol, sleep=sleeps.append)
        assert sleeps == []


def test_retry_refuses_to_wait_longer_than_max_delay():
    with pytest.raises(ProviderRateLimitError):
        call_with_retries(_flaky([ProviderRateLimitError("x", 3600.0)]),
                          RetryPolicy(max_delay=30), sleep=lambda s: pytest.fail("should not sleep"))


# ---- the real urllib transport against a local server --------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        if self.path.endswith("/limited"):
            self.send_response(429)
            self.send_header("Retry-After", "3")
            payload = {"error": {"message": "slow down"}}
        else:
            self.send_response(200)
            payload = {"model": "m", "stop_reason": "end_turn", "content": [{"type": "text", "text": "pong"}],
                       "usage": {"input_tokens": 1, "output_tokens": 1}}
        data = json.dumps(payload).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_port
    srv.shutdown()


def test_urllib_transport_end_to_end(server):
    p = AnthropicProvider("m", "key-1", base_url=server, timeout=5)
    assert p.complete(REQ).text == "pong"
    path, headers, body = _Handler.seen[-1]
    assert path == "/v1/messages" and headers["x-api-key"] == "key-1" and body["max_tokens"] == 123
    resp = UrllibTransport().post_json(server + "/limited", {}, {}, 5)
    assert resp.status == 429 and resp.headers["retry-after"] == "3"


def test_urllib_transport_connection_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(ProviderUnavailableError, match="network error"):
        UrllibTransport().post_json("http://127.0.0.1:%d/x" % port, {}, {}, 2)
