import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from axfilter.app import Config, create_app
from axfilter.oidc import OidcError, Verifier

KEYS = {"agent": "a", "viewer": "v", "admin": "d"}
ISS, AUD = "https://idp.example", "axfilter"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "k1"
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem, {"keys": [jwk]}


def mint(pem, groups, sub="u1", email=None, aud=AUD, iss=ISS, exp_delta=300):
    claims = {"iss": iss, "aud": aud, "sub": sub, "groups": groups,
              "exp": int(time.time()) + exp_delta}
    if email:
        claims["email"] = email
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "k1"})


def verifier(jwks):
    return Verifier(issuer=ISS, audience=AUD, role_claim="groups",
                    role_map={"sec-admins": "admin", "sec-viewers": "viewer"}, jwks=jwks)


def test_verify_maps_group_to_role_and_picks_highest(keypair):
    pem, jwks = keypair
    v = verifier(jwks)
    p = v.verify(mint(pem, ["sec-viewers", "sec-admins"], email="kim@corp.com"))
    assert p.role == "admin" and p.name == "kim@corp.com"


def test_verify_rejects_bad_aud_iss_and_unmapped(keypair):
    pem, jwks = keypair
    v = verifier(jwks)
    for tok in (mint(pem, ["sec-admins"], aud="other"),
                mint(pem, ["sec-admins"], iss="https://evil"),
                mint(pem, ["random-group"]),
                mint(pem, ["sec-admins"], exp_delta=-10)):
        with pytest.raises(OidcError):
            v.verify(tok)


def test_api_accepts_bearer_and_enforces_role(keypair):
    pem, jwks = keypair
    cfg = Config("sqlite:///:memory:", b"\x51" * 32, KEYS, oidc=verifier(jwks))
    # in-memory sqlite is per-connection; use a temp file instead for a stable store
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    cfg = Config(path, b"\x51" * 32, KEYS, oidc=verifier(jwks))
    c = TestClient(create_app(cfg))

    admin = {"Authorization": "Bearer " + mint(pem, ["sec-admins"], email="boss@corp.com")}
    viewer = {"Authorization": "Bearer " + mint(pem, ["sec-viewers"])}

    # viewer token: stats ok, admin endpoint forbidden
    assert c.get("/v1/stats/summary", headers=viewer).status_code == 200
    assert c.get("/v1/policy/history", headers=viewer).status_code == 403
    # admin token: policy update ok and audit actor is the token's email
    assert c.put("/v1/policy", headers=admin, json={}).status_code == 200
    hist = c.get("/v1/policy/history", headers=admin).json()
    assert hist[0]["actor"] == "boss@corp.com"
    # garbage bearer -> 401
    assert c.get("/v1/policy/history", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401
    os.remove(path)
