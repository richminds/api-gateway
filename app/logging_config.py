"""Structured (JSON) logging — one JSON object per line.

Same formatter as the sibling llm-gateway and knowledge-service, so the whole
platform's logs land in an aggregator with the same field names and one query
spans all of them. Every log aggregator built in the last decade (Datadog,
Loki, CloudWatch Logs Insights, ELK/OpenSearch, Google Cloud Logging) parses
JSON-per-line natively and indexes its fields, where a plain text line needs a
hand-written regex per deployment to get the same query power. No new external
service is involved — stdout stays the transport (``PYTHONUNBUFFERED=1`` is
set in the Dockerfile), only the encoding of each line changes.

Every record automatically carries the ambient ``request_id``, ``account_id``
and ``user_id`` from ``features/log_context.py``. The third one is what makes
this gateway's logs different from every other service's: it is the only place
that opens the token, so it is the only place that can put a real user on a
log line. "Show me everything user X did today, across every service" is a
field filter here and a guess anywhere else.

``APIGW_LOG_FORMAT=text`` reverts to a plain-text formatter for a local dev
terminal where a human is reading it live.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from features.log_context import get_account_id, get_request_id, get_user_id

# Attributes every stdlib LogRecord already has — anything else passed via
# logger.info(..., extra={...}) is assumed to be a deliberately-added
# structured field and gets folded into the JSON object.
_STANDARD_RECORD_ATTRS = frozenset(
    logging.LogRecord(
        name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None
    ).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JSONFormatter(logging.Formatter):
    """One JSON object per log line.

    Fixed fields: ``timestamp`` (ISO 8601 UTC), ``level``, ``logger``,
    ``message``, plus ``request_id`` / ``account_id`` / ``user_id`` from the
    ambient contextvars ("" when unset). Anything passed via ``extra={...}``
    is merged in as-is, so call sites can attach request-specific fields
    (``method``, ``path``, ``status``, ``latency_ms``, ``service``, ...)
    without this formatter needing to know about them in advance.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
            "account_id": get_account_id(),
            "user_id": get_user_id(),
        }

        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and key not in payload:
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        # ISO 8601 with milliseconds, UTC — the one timestamp shape every log
        # aggregator's auto-detection recognises without a custom pattern.
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + (
            f".{int(record.msecs):03d}Z"
        )


_TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def configure_logging(level: str, log_format: str = "json") -> None:
    """Install this module's log handler on the root logger.

    Safe to call more than once (e.g. every app startup in a test suite that
    builds the app repeatedly) and safe alongside other tooling that attaches
    its own root handler — such as pytest's ``caplog`` fixture.

    Only removes/replaces a handler THIS function installed previously (marked
    via an attribute on the handler instance); it never touches handlers
    belonging to something else. Replacing ``root.handlers`` wholesale is the
    obvious implementation and it silently breaks ``caplog``: pytest attaches
    its capture handler to the root logger, and wiping the list on every app
    boot — which happens once per test via the FastAPI lifespan — discards it
    before any test can assert on captured logs.
    """
    resolved_level = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(
        JSONFormatter() if log_format == "json" else logging.Formatter(_TEXT_FORMAT)
    )
    handler._api_gateway_managed = True  # type: ignore[attr-defined]

    root = logging.getLogger()
    root.setLevel(resolved_level)
    root.handlers = [
        h for h in root.handlers if not getattr(h, "_api_gateway_managed", False)
    ]
    root.addHandler(handler)
