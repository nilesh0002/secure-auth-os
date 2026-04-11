from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int = 0


class LoginRateLimiter:
    def __init__(self, attempts: int, window_seconds: int) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._events: dict[str, deque[datetime]] = defaultdict(deque)

    def allow(self, key: str) -> RateLimitDecision:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)
        events = self._events[key]
        while events and events[0] < window_start:
            events.popleft()
        if len(events) >= self.attempts:
            retry_after = int((events[0] + timedelta(seconds=self.window_seconds) - now).total_seconds())
            return RateLimitDecision(False, max(retry_after, 1))
        events.append(now)
        return RateLimitDecision(True, 0)
