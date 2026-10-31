from fastapi.testclient import TestClient

from axfilter.app import Config, create_app
from axfilter.ratelimit import RateLimiter

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


# ---- unit tests of the limiter core --------------------------------------

def test_burst_then_exhausted():
    clk = FakeClock()
    rl = RateLimiter(per_sec=5, per_day=0, clock=clk)
    # full bucket of 5 tokens: 5 requests pass back-to-back
    for _ in range(5):
        assert rl.check("x").allowed
    d = rl.check("x")
    assert not d.allowed and d.reason == "rate" and d.retry_after > 0


def test_refill_over_time():
    clk = FakeClock()
    rl = RateLimiter(per_sec=5, per_day=0, clock=clk)
    for _ in range(5):
        rl.check("x")
    assert not rl.check("x").allowed
    clk.advance(0.2)            # 0.2s * 5/s = 1 token refilled
    assert rl.check("x").allowed
    assert not rl.check("x").allowed


def test_quota_exhaustion():
    clk = FakeClock()
    rl = RateLimiter(per_sec=0, per_day=3, clock=clk)
    for _ in range(3):
        assert rl.check("x").allowed
    d = rl.check("x")
    assert not d.allowed and d.reason == "quota" and d.retry_after > 0
    # a denied request does not consume quota; still denied until the window resets
    assert not rl.check("x").allowed
    clk.advance(86400.0)        # next day window
    assert rl.check("x").allowed


def test_per_key_isolation():
    clk = FakeClock()
    rl = RateLimiter(per_sec=2, per_day=0, clock=clk)
    assert rl.check("a").allowed
    assert rl.check("a").allowed
    assert not rl.check("a").allowed
    # a different key has its own full bucket
    assert rl.check("b").allowed
    assert rl.check("b").allowed
    assert not rl.check("b").allowed


def test_unlimited_when_zero():
    rl = RateLimiter(per_sec=0, per_day=0)
    assert not rl.enabled
    for _ in range(1000):
        assert rl.check("x").allowed


def test_denied_rate_request_not_counted_against_quota():
    clk = FakeClock()
    rl = RateLimiter(per_sec=1, per_day=5, clock=clk)   # bucket capacity = 1 token
    assert rl.check("x").allowed           # token consumed, quota=1
    assert not rl.check("x").allowed       # rate-denied: must NOT count against quota
    # feed one token at a time; the single rate-denied call above must not have
    # consumed a quota slot, so all 5 quota slots remain for allowed requests.
    for _ in range(4):
        clk.advance(1.0)                    # refill 1 token (cap is 1)
        assert rl.check("x").allowed       # quota now 2,3,4,5
    clk.advance(1.0)
    d = rl.check("x")
    assert not d.allowed and d.reason == "quota"


# ---- API-level tests ------------------------------------------------------

def _body(ip="10.0.0.1"):
    return {"service": "ChatGPT", "user": "x", "ip": ip, "text": "hi"}


def test_api_429_with_retry_after(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x11" * 32, KEYS, rate_per_sec=3, rate_per_day=0)
    c = TestClient(create_app(cfg))
    hdr = {"X-API-Key": KEYS["agent"]}
    for _ in range(3):
        assert c.post("/v1/inspect", headers=hdr, json=_body()).status_code == 200
    r = c.post("/v1/inspect", headers=hdr, json=_body())
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert r.json()["reason"] == "rate"
    # security headers still decorate the 429
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_api_other_key_unaffected(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x12" * 32, KEYS, rate_per_sec=2, rate_per_day=0)
    c = TestClient(create_app(cfg))
    agent = {"X-API-Key": KEYS["agent"]}
    for _ in range(2):
        assert c.post("/v1/inspect", headers=agent, json=_body()).status_code == 200
    assert c.post("/v1/inspect", headers=agent, json=_body()).status_code == 429
    # admin key also has agent rank and its own independent bucket
    admin = {"X-API-Key": KEYS["admin"]}
    assert c.post("/v1/inspect", headers=admin, json=_body()).status_code == 200


def test_api_healthz_exempt(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x13" * 32, KEYS, rate_per_sec=1, rate_per_day=0)
    c = TestClient(create_app(cfg))
    for _ in range(10):
        assert c.get("/healthz").status_code == 200
