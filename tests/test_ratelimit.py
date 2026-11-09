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
    assert len(rl._hits[(0, None, "*")]) == 1


def test_per_client_limits_keep_a_budget_per_client():
    rl = RateLimiter([RateLimit("*", 1, 60, per_client=True), RateLimit("*", 3, 60)], clock=Clock())
    assert rl.check("a", "alice") is None
    assert "for this client" in rl.check("a", "alice")
    assert rl.check("a", "bob") is None
    assert rl.check("a", "carol") is None
    # The shared limit still caps everyone together.
    assert "for this client" not in rl.check("a", "dave")


def test_quiet_windows_are_swept():
    from mcp_warden import ratelimit

    clock = Clock()
    rl = RateLimiter([RateLimit("*", 5, 60, per_client=True)], clock=clock)
    for i in range(10):
        rl.check("a", f"session-{i}")
    clock.t = 120.0
    for _ in range(ratelimit.SWEEP_EVERY):
        rl.check("a", "live")
    assert {k[1] for k in rl._hits} == {"live"}
