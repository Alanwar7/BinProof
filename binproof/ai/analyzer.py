"""FunctionAnalyzer: orchestration only.

context (from Analysis) -> prompt -> provider (with retries) -> parse/validate
(with one repair round) -> record. It owns no provider, prompt or schema
details, so other analyses (whole-program, evidence verification) can reuse
the same pieces.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

from ..addresses import AddressLike
from ..analysis import Analysis
from ..errors import BinProofError
from .context import ContextLimits, FunctionContext, build_function_context
from .errors import MalformedAIResponseError
from .models import FunctionAnalysisRecord, FunctionIdentity, Provenance
from .parsing import parse_function_analysis
from .prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_repair_message, render_user_prompt
from .providers.base import LLMProvider, LLMRequest, Message
from .retry import RetryPolicy, call_with_retries


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FunctionAnalyzer:
    def __init__(self, analysis: Analysis, provider: LLMProvider, *,
                 limits: Optional[ContextLimits] = None,
                 retry: Optional[RetryPolicy] = None,
                 max_repair_attempts: int = 1,
                 max_tokens: int = 4096,
                 temperature: Optional[float] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 on_retry: Optional[Callable[[Exception, float, int], None]] = None,
                 clock: Callable[[], str] = _utc_now):
        self._analysis = analysis
        self._provider = provider
        self._limits = limits or ContextLimits()
        self._retry = retry or RetryPolicy()
        self._max_repair = max(0, max_repair_attempts)
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._sleep = sleep
        self._on_retry = on_retry
        self._clock = clock

    def build_context(self, address: AddressLike) -> FunctionContext:
        return build_function_context(self._analysis, address, self._limits)

    def analyze(self, address: AddressLike) -> FunctionAnalysisRecord:
        return self.analyze_context(self.build_context(address))

    def analyze_context(self, ctx: FunctionContext) -> FunctionAnalysisRecord:
        messages: List[Message] = [Message("user", render_user_prompt(ctx))]
        attempts = 0
        tokens_in: Optional[int] = None
        tokens_out: Optional[int] = None

        while True:
            attempts += 1
            request = LLMRequest(SYSTEM_PROMPT, tuple(messages), self._max_tokens, self._temperature)
            response = call_with_retries(lambda: self._provider.complete(request), self._retry,
                                         sleep=self._sleep, on_retry=self._on_retry)
            if response.input_tokens is not None:
                tokens_in = (tokens_in or 0) + response.input_tokens
            if response.output_tokens is not None:
                tokens_out = (tokens_out or 0) + response.output_tokens
            try:
                analysis = parse_function_analysis(response.text, truncated=response.truncated)
                break
            except MalformedAIResponseError as exc:
                # A cut-off answer will not be fixed by asking again; other failures get a repair round.
                if exc.truncated or attempts > self._max_repair:
                    raise
                messages.append(Message("assistant", response.text.strip() or "(empty response)"))
                messages.append(Message("user", build_repair_message(exc.problem)))

        return FunctionAnalysisRecord(
            function=FunctionIdentity(address=ctx.address, name=ctx.name, signature=ctx.signature),
            analysis=analysis,
            context_notes=list(ctx.notes),
            provenance=Provenance(
                provider=self._provider.name, model=self._provider.model, created_at=self._clock(),
                prompt_version=PROMPT_VERSION, context_sha256=ctx.sha256(), attempts=attempts,
                input_tokens=tokens_in, output_tokens=tokens_out, **self._program_facts()),
        )

    def _program_facts(self) -> dict:
        facts = {"program_name": self._analysis.manifest.program_name, "program_sha256": None}
        try:
            facts["program_sha256"] = self._analysis.metadata.sha256
        except BinProofError:
            pass
        return facts
