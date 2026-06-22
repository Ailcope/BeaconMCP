"""Cloudflare 401 diagnostic tests.

When an MCP request reaches BeaconMCP without a usable ``Authorization``
header but *with* Cloudflare's ``cf-ray`` edge header, the server enriches the
401 body with an actionable ``hint`` (and logs a warning) because a Cloudflare
WAF / Access / Bot-Fight-Mode rule is the overwhelmingly likely cause of the
stripped/blocked header. See ``docs/cloudflare.md``.

These tests exercise the real ``_build_unauthorized_body`` helper through a
Starlette ``TestClient`` so the full body + header contract is covered the same
way ``auth_middleware`` wires it in production. The status code (401) and the
``WWW-Authenticate`` header MUST stay unchanged regardless of the hint --
OAuth discovery depends on them.

Run with::

    pytest tests/test_cloudflare_diagnostic.py -v
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from beaconmcp.__main__ import _CF_EDGE_HEADER, _build_unauthorized_body

# The substring the maintainer-facing hint must point operators at.
_HINT_MARKER = "docs/cloudflare.md"
_RESOURCE_META = (
    "https://mcp.example.com/.well-known/oauth-protected-resource"
)


@pytest.fixture()
def client() -> TestClient:
    """A minimal app whose /mcp guard reproduces auth_middleware's
    missing/invalid-bearer 401 branch via the shared helper."""

    async def mcp_endpoint(_request: Request) -> Response:
        # Only reached when a valid bearer is present; the middleware short-
        # circuits unauthenticated requests before this runs.
        return JSONResponse({"ok": True})

    async def guard(request: Request, call_next):
        if request.url.path == "/mcp":
            authorization = request.headers.get("authorization", "")
            if not authorization.startswith("Bearer "):
                return JSONResponse(
                    _build_unauthorized_body(
                        request.headers, error="unauthorized"
                    ),
                    status_code=401,
                    headers={
                        "WWW-Authenticate": (
                            'Bearer realm="beaconmcp", '
                            f'resource_metadata="{_RESOURCE_META}"'
                        ),
                    },
                )
        return await call_next(request)

    app = Starlette(
        routes=[Route("/mcp", mcp_endpoint, methods=["GET", "POST"])],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=guard)],
    )
    return TestClient(app)


@pytest.mark.parametrize("method", ["get", "post"])
def test_mcp_no_auth_with_cf_ray_returns_hint(
    client: TestClient, method: str, caplog
) -> None:
    """No Authorization + cf-ray -> 401 carrying the Cloudflare hint, with the
    WWW-Authenticate header intact and a logged warning."""
    with caplog.at_level(logging.WARNING, logger="beaconmcp"):
        resp = getattr(client, method)(
            "/mcp", headers={_CF_EDGE_HEADER: "7d9f0c2a1b3e4f56-AMS"}
        )

    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "unauthorized"
    assert "hint" in body
    assert _HINT_MARKER in body["hint"]
    # OAuth discovery contract preserved.
    assert "WWW-Authenticate" in resp.headers
    assert resp.headers["WWW-Authenticate"].startswith("Bearer realm=")
    # Operator-facing breadcrumb in the logs.
    assert any("Cloudflare" in r.message for r in caplog.records)


@pytest.mark.parametrize("method", ["get", "post"])
def test_mcp_no_auth_without_cf_ray_has_no_hint(
    client: TestClient, method: str, caplog
) -> None:
    """A normal direct unauthenticated request (no cf-ray) keeps the minimal
    body -- no Cloudflare-specific hint and no warning, but still a 401 with
    the WWW-Authenticate header."""
    with caplog.at_level(logging.WARNING, logger="beaconmcp"):
        resp = getattr(client, method)("/mcp")

    assert resp.status_code == 401
    body = resp.json()
    assert body == {"error": "unauthorized"}
    assert "hint" not in body
    assert "WWW-Authenticate" in resp.headers
    assert not any("Cloudflare" in r.message for r in caplog.records)


def test_invalid_token_with_cf_ray_gets_hint() -> None:
    """The helper enriches any error code (e.g. invalid_token), not just
    unauthorized, when cf-ray is present."""
    body = _build_unauthorized_body(
        {_CF_EDGE_HEADER: "abc-AMS"}, error="invalid_token"
    )
    assert body["error"] == "invalid_token"
    assert _HINT_MARKER in body["hint"]


def test_helper_minimal_body_without_cf_ray() -> None:
    """Direct unit check: no edge header -> minimal body, no hint key."""
    body = _build_unauthorized_body({}, error="unauthorized")
    assert body == {"error": "unauthorized"}
