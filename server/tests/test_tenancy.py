"""Optional multi-tenancy: events, policy and stats isolate per tenant.

The default tenant must behave exactly as the pre-tenancy single-tenant
service did (no X-Tenant header == tenant "default").
"""
import pytest
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


@pytest.fixture
def client(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x07" * 32, KEYS)
    return TestClient(create_app(cfg))


def h(role, tenant=None):
    hd = {"X-API-Key": KEYS[role]}
    if tenant is not None:
        hd["X-Tenant"] = tenant
    return hd


def inspect(client, text, tenant=None, service="ChatGPT", ip="192.168.1.101"):
    return client.post("/v1/inspect", headers=h("agent", tenant),
                       json={"service": service, "user": "kim", "ip": ip, "text": text}).json()


def test_default_tenant_unchanged_without_header(client):
    # Behaves identically to the single-tenant service.
    assert inspect(client, "문의: a@b.com")["action"] == "mask"
    assert inspect(client, "카드 4539 1488 0343 6467")["action"] == "block"
    assert inspect(client, "안녕하세요")["action"] == "allow"
    s = client.get("/v1/stats/summary?period=today", headers=h("viewer")).json()
    assert (s["total"], s["detected"], s["blocked"], s["masked"], s["allowed"]) == (3, 2, 1, 1, 2)


def test_omitting_header_equals_explicit_default(client):
    inspect(client, "a@b.com")                       # no header -> "default"
    inspect(client, "a@b.com", tenant="default")     # explicit default
    s_implicit = client.get("/v1/stats/summary?period=today", headers=h("viewer")).json()
    s_explicit = client.get("/v1/stats/summary?period=today",
                            headers=h("viewer", "default")).json()
    assert s_implicit["total"] == s_explicit["total"] == 2


def test_events_isolated_per_tenant(client):
    inspect(client, "a@b.com", tenant="acme")
    inspect(client, "a@b.com", tenant="acme")
    inspect(client, "a@b.com", tenant="globex")

    acme = client.get("/v1/stats/summary?period=today", headers=h("viewer", "acme")).json()
    globex = client.get("/v1/stats/summary?period=today", headers=h("viewer", "globex")).json()
    default = client.get("/v1/stats/summary?period=today", headers=h("viewer")).json()
    assert acme["total"] == 2
    assert globex["total"] == 1
    assert default["total"] == 0          # default tenant never saw these events

    acme_events = client.get("/v1/events", headers=h("viewer", "acme")).json()
    globex_events = client.get("/v1/events", headers=h("viewer", "globex")).json()
    assert len(acme_events) == 2 and len(globex_events) == 1


def test_two_tenants_do_not_see_each_others_data(client):
    inspect(client, "secret a@b.com", tenant="acme")
    inspect(client, "other c@d.com", tenant="globex")

    # Each tenant's event id exists only within its own tenant for admin reads.
    acme_ev = client.get("/v1/events", headers=h("viewer", "acme")).json()
    globex_ev = client.get("/v1/events", headers=h("viewer", "globex")).json()
    acme_id, globex_id = acme_ev[0]["id"], globex_ev[0]["id"]

    # globex cannot read acme's original (cross-tenant -> 404), and vice versa.
    assert client.get(f"/v1/events/{acme_id}/original", headers=h("admin", "globex")).status_code == 404
    assert client.get(f"/v1/events/{globex_id}/original", headers=h("admin", "acme")).status_code == 404
    # but each tenant can read its own.
    assert client.get(f"/v1/events/{acme_id}/original",
                      headers=h("admin", "acme")).json()["original"] == "secret a@b.com"
    assert client.get(f"/v1/events/{globex_id}/original",
                      headers=h("admin", "globex")).json()["original"] == "other c@d.com"


def test_policy_isolated_per_tenant(client):
    # acme blocks perplexity; globex and default keep defaults.
    acme_policy = {"services": {"perplexity": "block"}}
    assert client.put("/v1/policy", headers=h("admin", "acme"), json=acme_policy).status_code == 200

    # acme sees its policy change; globex does not.
    assert client.get("/v1/policy", headers=h("viewer", "acme")).json()["services"] == {"perplexity": "block"}
    assert client.get("/v1/policy", headers=h("viewer", "globex")).json()["services"] == {}
    assert client.get("/v1/policy", headers=h("viewer")).json()["services"] == {}  # default

    # policy decision honours the tenant's own policy.
    assert inspect(client, "hi", tenant="acme", service="Perplexity")["reason"] == "SERVICE_BLOCKED"
    assert inspect(client, "hi", tenant="globex", service="Perplexity")["action"] == "allow"


def test_policy_history_isolated_per_tenant(client):
    client.put("/v1/policy", headers=h("admin", "acme"), json={"block_message": "acme msg"})
    client.put("/v1/policy", headers=h("admin", "globex"), json={"block_message": "globex msg"})
    client.put("/v1/policy", headers=h("admin", "acme"), json={"block_message": "acme msg 2"})

    acme_hist = client.get("/v1/policy/history", headers=h("admin", "acme")).json()
    globex_hist = client.get("/v1/policy/history", headers=h("admin", "globex")).json()
    assert len(acme_hist) == 2 and all(e["tenant"] == "acme" for e in acme_hist)
    assert len(globex_hist) == 1 and globex_hist[0]["tenant"] == "globex"

    # A tenant cannot fetch another tenant's policy version by id.
    globex_vid = globex_hist[0]["id"]
    assert client.get(f"/v1/policy/history/{globex_vid}", headers=h("admin", "acme")).status_code == 404
    assert client.get(f"/v1/policy/history/{globex_vid}", headers=h("admin", "globex")).status_code == 200


def test_invalid_tenant_header_rejected(client):
    r = client.get("/v1/stats/summary", headers={"X-API-Key": KEYS["viewer"], "X-Tenant": "bad tenant!"})
    assert r.status_code == 422


def test_store_level_tenant_isolation(tmp_path):
    # Directly exercise the Store tenant arguments (backend-agnostic SQLite).
    from axfilter.keys import LocalMasterKeyProvider
    from axfilter.policy import Policy
    from axfilter.store import Store

    s = Store(str(tmp_path / "s.db"), LocalMasterKeyProvider(b"\x09" * 32))
    s.add_event(service="chatgpt", user="u", ip="10.0.0.1", group="g", direction="input",
                action="allow", reason=None, finding_types=[], latency_ms=1.0,
                masked_text=None, original="x", tenant="acme")
    s.add_event(service="chatgpt", user="u", ip="10.0.0.1", group="g", direction="input",
                action="allow", reason=None, finding_types=[], latency_ms=1.0,
                masked_text=None, original="y")  # default tenant

    now = __import__("time").time()
    assert s.summary(0, "all", "acme")["total"] == 1
    assert s.summary(0, "all", "default")["total"] == 1
    assert s.summary(0, "all")["total"] == 2            # None = all tenants

    s.set_policy(Policy(block_message="acme"), actor="admin", tenant="acme")
    assert s.get_policy("acme").block_message == "acme"
    assert s.get_policy("default").block_message != "acme"
    assert len(s.policy_history(tenant="acme")) == 1
    assert len(s.policy_history()) == 1                  # None = all tenants
