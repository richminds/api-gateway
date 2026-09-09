"""Service-level configuration for the API Gateway HTTP server.

Env-var prefix: ``APIGW_``.

Deliberately separate from ``features/config.py`` (prefix ``GATEWAY_``): that
file owns *what the gateway fronts and what it trusts*, this one owns *how the
gateway itself is exposed* (host/port/CORS/docs/logging). Same split the
sibling services use — llm-gateway's ``features/config.py`` vs
``app/config.py``, knowledge-service's ``rag/config.py`` vs ``app/config.py``,
auth-service's ``features/config.py`` vs ``app/config.py``.

CORS matters more here than in any of them. The gateway is the only origin a
browser app talks to — the UIs call this service and nothing else — so if an
origin is not allowed here, that UI is broken, and no amount of configuration
on llm-gateway or knowledge-service will help.
"""
from __future__ import annotations

import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent


class ServiceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APIGW_",
        env_file=str(_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------- server
    host: str = "0.0.0.0"
    port: int = 8000
    """8000 is the front door. The services behind it keep their own ports —
    llm-gateway 8080, knowledge-service 8090, auth-service 8100 — which stay
    private in a real deployment: only this port should be reachable."""

    root_path: str = ""          # set when behind a path-prefixing proxy
    log_level: str = "INFO"
    log_format: str = "json"     # "json" (default, aggregator-friendly) | "text"
    environment: str = "development"  # development | staging | production

    # ------------------------------------------------------------- docs
    docs_enabled: bool = True    # set false in production if the API is public

    # ------------------------------------------------------------- CORS
    # Comma-separated origins. Browsers only — service-to-service callers are
    # unaffected. See the module docstring for why this is the one place that
    # can get a UI working or leave it broken.
    cors_origins: str = ""

    # Vercel gives every deployment and every preview its own hostname
    # (knowledge-ingest-ui-<hash>-<scope>.vercel.app), so an exact allowlist
    # goes stale on each deploy and previews are broken by default. A regex
    # covers the whole family in one rule — anchor it to the projects you
    # actually own, never leave it open.
    cors_origin_regex: str = ""

    # ------------------------------------------------------------- misc
    request_id_header: str = "X-Request-ID"
    """Echoed back on every response and forwarded upstream, so one ID ties the
    gateway's access log, auth-service's log and the upstream's log together
    for a single call."""

    expose_config_endpoint: bool = True
    """Expose resolved (non-secret) configuration on GET /v1/config. Admin-only
    either way — see app/dependencies.py."""

    trust_forwarded_for: bool = False
    """Whether to believe an inbound ``X-Forwarded-For`` when identifying the
    client IP for anonymous rate limiting.

    Off by default, and that default is the safe one: if the gateway is exposed
    directly, anyone can send that header and rotate a fake IP per request,
    which turns the sign-in rate limit into no rate limit at all. Turn it on
    only when a load balancer you control sits in front and overwrites the
    header — which is exactly when the socket address is the balancer's and
    the header is the only way to see the real client.
    """

    # ---------------------------------------------------------- derived

    def parsed_cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")


service_settings = ServiceSettings()
