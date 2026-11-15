"""Authenticated Streamable HTTP entrypoint for the hosted archive tools.

The local stdio entrypoint is unchanged. HTTP refuses to start until its
public URL and Auth0 issuer are configured.
"""
from __future__ import annotations

import asyncio
import os
from urllib.parse import urlsplit

import jwt
import uvicorn
from jwt import PyJWKClient
from starlette.responses import JSONResponse, Response

from mcp.server.transport_security import TransportSecuritySettings

from .server import mcp

REQUIRED_SCOPE = "read:archives"


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError(f"{label} must be a complete HTTPS URL without query or fragment")
    return value.rstrip("/")


class Auth0Gate:
    """Verify every MCP HTTP request before it reaches the MCP application."""

    def __init__(self, app, *, issuer: str, resource: str):
        self.app = app
        self.issuer = issuer.rstrip("/") + "/"
        self.resource = resource
        self.jwks = PyJWKClient(self.issuer + ".well-known/jwks.json", cache_jwk_set=True)
        public_origin = resource.removesuffix("/mcp")
        self.metadata_path = "/.well-known/oauth-protected-resource/mcp"
        self.metadata_url = public_origin + self.metadata_path

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # The MCP Streamable HTTP session manager is initialized here.
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        path = scope.get("path", "")
        if path == self.metadata_path:
            response = JSONResponse({
                "resource": self.resource,
                "authorization_servers": [self.issuer],
                "scopes_supported": [REQUIRED_SCOPE],
                "bearer_methods_supported": ["header"],
            })
            await response(scope, receive, send)
            return

        # Only the MCP HTTP endpoint is exposed. No unprotected health or
        # administration routes are introduced by this entrypoint.
        if path not in ("/mcp", "/mcp/"):
            await Response(status_code=404)(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        if not auth_header.lower().startswith("bearer "):
            await self._deny(scope, receive, send)
            return

        token = auth_header[7:].strip()
        if not token:
            await self._deny(scope, receive, send)
            return

        try:
            claims = await asyncio.to_thread(self._verify_jwt, token)
        except (jwt.PyJWTError, ValueError, OSError, TimeoutError):
            await self._deny(scope, receive, send)
            return

        raw_permissions = claims.get("permissions", [])
        raw_scope = claims.get("scope", "")
        permissions = raw_permissions if isinstance(raw_permissions, list) else []
        scopes = raw_scope.split() if isinstance(raw_scope, str) else []
        if REQUIRED_SCOPE not in permissions and REQUIRED_SCOPE not in scopes:
            await self._deny(scope, receive, send, insufficient_scope=True)
            return

        await self.app(scope, receive, send)

    def _verify_jwt(self, token: str) -> dict:
        signing_key = self.jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.resource,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            leeway=30,
        )
        return claims

    async def _deny(self, scope, receive, send, *, insufficient_scope=False):
        error = "insufficient_scope" if insufficient_scope else "invalid_token"
        challenge = (
            f'Bearer error="{error}", '
            f'resource_metadata="{self.metadata_url}", '
            f'scope="{REQUIRED_SCOPE}"'
        )
        response = JSONResponse(
            {"error": error},
            status_code=403 if insufficient_scope else 401,
            headers={"WWW-Authenticate": challenge, "Cache-Control": "no-store"},
        )
        await response(scope, receive, send)


def create_app():
    issuer = _https_url(os.environ["AUTH0_ISSUER"], "AUTH0_ISSUER")
    public_url = _https_url(os.environ["MCP_PUBLIC_URL"], "MCP_PUBLIC_URL")
    if urlsplit(public_url).username or urlsplit(public_url).password:
        raise ValueError("MCP_PUBLIC_URL cannot contain userinfo")
    if not public_url.endswith("/mcp"):
        raise ValueError("MCP_PUBLIC_URL must end with /mcp")
    return Auth0Gate(
        mcp.streamable_http_app(
            stateless_http=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[urlsplit(public_url).netloc],
            ),
        ),
        issuer=issuer,
        resource=public_url,
    )


def main():
    app = create_app()  # Fail closed when configuration is incomplete.
    uvicorn.run(
        app,
        host=os.environ.get("MCP_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "10000")),
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


if __name__ == "__main__":
    main()
