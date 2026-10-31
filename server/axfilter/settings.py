"""Central configuration. Every runtime knob is declared here and read from the
environment (prefix AXFILTER_), so deployment is 'set env vars' and nothing else."""
from __future__ import annotations

import secrets
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AXFILTER_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    database_url: str = ""            # e.g. postgresql+psycopg2://user:pw@host/db; empty -> sqlite file

    agent_key: str = ""
    viewer_key: str = ""
    admin_key: str = ""

    key_provider: str = "local"       # local | awskms
    kms_key_id: str = ""
    data_key: str = ""                # hex master key for the local provider

    require_tls: bool = False
    trusted_proxy: bool = False
    cors_origins: str = ""            # comma-separated

    max_auth_failures: int = 10
    auth_window_seconds: float = 300.0
    auth_lockout_seconds: float = 300.0

    log_level: str = "INFO"
    log_json: bool = True

    # SIEM forwarding (metadata only)
    siem_sink: str = "none"          # none | file | udp
    siem_format: str = "cef"         # cef | syslog | json
    siem_target: str = ""            # file path, or host:port for udp

    # OIDC SSO (bearer tokens, in addition to API keys)
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_jwks_json: str = ""          # inline JWKS for air-gapped / testing
    oidc_role_claim: str = "groups"
    oidc_role_map: str = ""           # JSON: {"idp-group": "admin", ...}

    # LLM egress gateway (OpenAI-compatible reverse proxy that enforces inspection)
    gateway_upstream: str = ""        # provider base URL, e.g. https://api.openai.com
    gateway_upstream_key: str = ""

    # Optional transformer NER model (augments rule-based name/address detection)
    ner_model: str = ""               # HF model name; empty disables the model adapter
    ner_threshold: float = 0.5        # minimum entity score to accept a span

    def resolved_keys(self) -> dict[str, str]:
        out = {}
        for role in ("agent", "viewer", "admin"):
            v = getattr(self, f"{role}_key")
            if not v:
                v = secrets.token_urlsafe(24)
                print(f"[axfilter] AXFILTER_{role.upper()}_KEY not set; temporary {role} key: {v}")
            out[role] = v
        return out

    def cors_list(self) -> tuple[str, ...]:
        return tuple(o.strip() for o in self.cors_origins.split(",") if o.strip())
