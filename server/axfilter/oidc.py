"""OIDC bearer-token verification for SSO.

Verifies an RS256 ID/access token against the IdP's JWKS, checks issuer/audience/
expiry, and maps an OIDC group/role claim to an AX Filter role (agent/viewer/admin).
Works air-gapped if the JWKS is supplied directly (AXFILTER_OIDC_JWKS_JSON).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import NamedTuple

import jwt
from jwt.algorithms import RSAAlgorithm

ROLE_RANK = {"agent": 0, "viewer": 1, "admin": 2}


class Principal(NamedTuple):
    name: str
    role: str

    def __str__(self) -> str:        # used as the audit actor
        return self.name


class OidcError(Exception):
    pass


class Verifier:
    def __init__(self, *, issuer: str, audience: str, role_claim: str = "groups",
                 role_map: dict[str, str] | None = None, jwks: dict | None = None,
                 jwks_url: str | None = None, cache_seconds: int = 3600):
        self.issuer = issuer
        self.audience = audience
        self.role_claim = role_claim
        self.role_map = role_map or {}
        self._jwks_static = jwks
        self.jwks_url = jwks_url
        self._cache_seconds = cache_seconds
        self._keys: dict[str, object] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def _load_jwks(self) -> dict:
        if self._jwks_static is not None:
            return self._jwks_static
        with urllib.request.urlopen(self.jwks_url, timeout=5) as r:   # nosec - configured IdP
            return json.loads(r.read())

    def _key_for(self, kid: str):
        with self._lock:
            fresh = time.time() - self._fetched_at < self._cache_seconds
            if not self._keys or not fresh or kid not in self._keys:
                jwks = self._load_jwks()
                self._keys = {k["kid"]: RSAAlgorithm.from_jwk(json.dumps(k)) for k in jwks["keys"]}
                self._fetched_at = time.time()
            if kid not in self._keys:
                raise OidcError("unknown key id")
            return self._keys[kid]

    def _map_role(self, claims: dict) -> str | None:
        raw = claims.get(self.role_claim, [])
        groups = raw if isinstance(raw, list) else [raw]
        roles = [self.role_map[g] for g in groups if g in self.role_map]
        return max(roles, key=lambda r: ROLE_RANK.get(r, -1)) if roles else None

    def verify(self, token: str) -> Principal:
        try:
            kid = jwt.get_unverified_header(token).get("kid", "")
            key = self._key_for(kid)
            claims = jwt.decode(token, key=key, algorithms=["RS256"],
                                audience=self.audience, issuer=self.issuer)
        except OidcError:
            raise
        except Exception as e:
            raise OidcError(f"token verification failed: {e}") from e
        role = self._map_role(claims)
        if not role:
            raise OidcError("no mapped role in token")
        name = claims.get("email") or claims.get("preferred_username") or claims.get("sub") or "oidc-user"
        return Principal(str(name), role)


def verifier_from_settings(st) -> Verifier | None:
    if not getattr(st, "oidc_issuer", ""):
        return None
    jwks = json.loads(st.oidc_jwks_json) if getattr(st, "oidc_jwks_json", "") else None
    role_map = json.loads(st.oidc_role_map) if getattr(st, "oidc_role_map", "") else {}
    return Verifier(issuer=st.oidc_issuer, audience=st.oidc_audience,
                    role_claim=st.oidc_role_claim or "groups", role_map=role_map,
                    jwks=jwks, jwks_url=st.oidc_jwks_url or None)
