"""Egress gateway: enforce inspection on OpenAI-compatible API traffic, with a
mocked upstream so we assert exactly what would reach the provider."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app

KEYS = {"agent": "a", "viewer": "v", "admin": "d"}


@pytest.fixture
def seen():
    return {}


@pytest.fixture
def client(tmp_path, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"id": "cmpl-1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})
    mock = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://upstream.test")
    cfg = Config(str(tmp_path / "g.db"), b"\x61" * 32, KEYS,
                 gateway_upstream="https://upstream.test", gateway_upstream_key="UPSTREAM-KEY",
                 http_client=mock)
    return TestClient(create_app(cfg))


def call(client, text, role="user"):
    return client.post("/gateway/v1/chat/completions", headers={"X-API-Key": "a"},
                       json={"model": "gpt-4o", "messages": [{"role": role, "content": text}]})


def test_allow_forwards_unchanged(client, seen):
    r = call(client, "분기 매출을 요약해줘")
    assert r.status_code == 200 and r.json()["choices"][0]["message"]["content"] == "ok"
    assert seen["body"]["messages"][0]["content"] == "분기 매출을 요약해줘"
    assert seen["auth"] == "Bearer UPSTREAM-KEY"       # gateway injects the provider key


def test_mask_rewrites_before_forwarding(client, seen):
    r = call(client, "고객 메일 hong@corp.com 로 보내줘")
    assert r.status_code == 200
    fwd = seen["body"]["messages"][0]["content"]
    assert "[이메일]" in fwd and "hong@corp.com" not in fwd   # masked before leaving the network


def test_block_never_reaches_upstream(client, seen):
    seen.clear()
    r = call(client, "주민번호 900101-1234567 조회해줘")
    assert r.status_code == 403
    assert r.json()["detail"]["blocked_by"] == "axfilter-gateway"
    assert "RRN" in r.json()["detail"]["findings"]
    assert "body" not in seen                               # upstream was never called


def test_gateway_requires_auth(client):
    assert client.post("/gateway/v1/chat/completions",
                       json={"messages": [{"role": "user", "content": "x"}]}).status_code == 401


def test_gateway_records_event(client):
    call(client, "카드 4539 1488 0343 6467 결제")
    ev = client.get("/v1/events?action=block", headers={"X-API-Key": "d"}).json()
    assert any(e["service"] == "gateway" for e in ev)
