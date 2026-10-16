from mcp_warden.policy import RateLimit
from mcp_warden.ratelimit import RateLimiter


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_sliding_window_per_tool():
    clock = Clock()
    rl = RateLimiter([RateLimit("search", 2, 10)], clock=clock)
    assert rl.check("search") is None
    assert rl.check("search") is None
    assert "rate limit" in rl.check("search")
    clock.t = 10.0
    assert rl.check("search") is None
    assert rl.check("other") is None


def test_glob_limit_is_shared_budget():
    rl = RateLimiter([RateLimit("*", 2, 60)], clock=Clock())
    assert rl.check("a") is None
    assert rl.check("b") is None
    assert rl.check("c") is not None


def test_denied_calls_do_not_consume_budget_of_other_limits():
    clock = Clock()
    rl = RateLimiter([RateLimit("*", 100, 60), RateLimit("write", 1, 60)], clock=clock)
    assert rl.check("write") is None
    assert rl.check("write") is not None
    assert rl.check("write") is not None
    # Only the one allowed write was recorded against the shared budget.
    assert len(rl._hits[(0, "*")]) == 1
