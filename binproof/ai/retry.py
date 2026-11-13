"""Provider-independent retry policy for rate limits and transient outages."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar

from .errors import ProviderRateLimitError, ProviderUnavailableError

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4          # total tries, including the first
    base_delay: float = 2.0        # seconds; doubles each retry
    max_delay: float = 60.0        # never wait longer than this
    jitter: float = 0.1            # fraction of the delay added at random


def call_with_retries(fn: Callable[[], T], policy: RetryPolicy, *,
                      sleep: Callable[[float], None] = time.sleep,
                      on_retry: Optional[Callable[[Exception, float, int], None]] = None) -> T:
    """Call fn(); retry rate-limit and unavailable errors, re-raise everything else.

    If a provider asks us to wait longer than max_delay we raise instead of
    blocking for minutes; the error message carries the retry-after hint.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except (ProviderRateLimitError, ProviderUnavailableError) as exc:
            if attempt >= policy.max_attempts:
                raise
            hint = getattr(exc, "retry_after", None)
            if hint is not None and hint > policy.max_delay:
                raise
            delay = hint if hint is not None else policy.base_delay * (2 ** (attempt - 1))
            delay = min(delay, policy.max_delay)
            delay += delay * policy.jitter * random.random()
            if on_retry:
                on_retry(exc, delay, attempt)
            sleep(delay)
