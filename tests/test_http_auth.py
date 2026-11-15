"""Basic security regression checks for the public MCP HTTP boundary."""
import asyncio

from norway_archives_mcp.http_server import Auth0Gate


async def _app(scope, receive, send):
    raise AssertionError("Unauthenticated request reached MCP app")


async def _request(gate, path="/mcp", headers=None):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await gate(
        {"type": "http", "method": "POST", "path": path, "headers": headers or []},
        receive,
        send,
    )
    return messages


def test_missing_token_returns_401_with_discovery():
    gate = Auth0Gate(
        _app,
        issuer="https://example.us.auth0.com",
        resource="https://archives.onrender.com/mcp",
    )
    response = asyncio.run(_request(gate))
    assert response[0]["status"] == 401
    headers = dict(response[0]["headers"])
    assert b"www-authenticate" in headers
    assert b"resource_metadata" in headers[b"www-authenticate"]


def test_metadata_is_public_and_lists_issuer():
    gate = Auth0Gate(
        _app,
        issuer="https://example.us.auth0.com",
        resource="https://archives.onrender.com/mcp",
    )
    response = asyncio.run(_request(gate, gate.metadata_path))
    assert response[0]["status"] == 200
    assert b"https://example.us.auth0.com/" in response[1]["body"]


def test_unrecognized_path_is_not_proxied():
    gate = Auth0Gate(
        _app,
        issuer="https://example.us.auth0.com",
        resource="https://archives.onrender.com/mcp",
    )
    response = asyncio.run(_request(gate, "/admin"))
    assert response[0]["status"] == 404


def test_bad_token_is_rejected():
    gate = Auth0Gate(
        _app,
        issuer="https://example.us.auth0.com",
        resource="https://archives.onrender.com/mcp",
    )
    response = asyncio.run(
        _request(gate, headers=[(b"authorization", b"Bearer clearly-not-a-jwt")])
    )
    assert response[0]["status"] == 401


def test_missing_scope_is_forbidden(monkeypatch):
    gate = Auth0Gate(
        _app,
        issuer="https://example.us.auth0.com",
        resource="https://archives.onrender.com/mcp",
    )
    monkeypatch.setattr(gate, "_verify_jwt", lambda _: {"scope": "openid profile"})
    response = asyncio.run(
        _request(gate, headers=[(b"authorization", b"Bearer valid-mock-token")])
    )
    assert response[0]["status"] == 403


def test_permission_grants_access_to_mcp_app(monkeypatch):
    seen = []

    async def protected_app(scope, receive, send):
        seen.append(scope["path"])
        await Response(status_code=204)(scope, receive, send)

    from starlette.responses import Response

    gate = Auth0Gate(
        protected_app,
        issuer="https://example.us.auth0.com",
        resource="https://archives.onrender.com/mcp",
    )
    monkeypatch.setattr(gate, "_verify_jwt", lambda _: {"permissions": ["read:archives"]})
    response = asyncio.run(
        _request(gate, headers=[(b"authorization", b"Bearer valid-mock-token")])
    )
    assert response[0]["status"] == 204
    assert seen == ["/mcp"]
