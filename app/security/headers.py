"""Security headers and request-size limiting, implemented as pure ASGI middleware."""
from __future__ import annotations

import re

from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSP = (
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)

STATIC_HEADERS: dict[bytes, bytes] = {
    b"content-security-policy": CSP.encode(),
    b"referrer-policy": b"no-referrer",
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"permissions-policy": b"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
    b"microphone=(), payment=(), usb=(), interest-cohort=()",
    b"cross-origin-opener-policy": b"same-origin",
    b"cross-origin-resource-policy": b"same-origin",
}


class SecurityHeadersMiddleware:
    """Adds hardening headers; marks everything outside /static as non-cacheable."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_static = scope["path"].startswith("/static/")
        versioned = b"v=" in scope.get("query_string", b"")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in STATIC_HEADERS and k.lower() != b"server"
                ]
                headers.extend(STATIC_HEADERS.items())
                if not any(k.lower() == b"cache-control" for k, _ in headers):
                    if not is_static:
                        headers.append((b"cache-control", b"no-store"))
                    elif versioned:
                        # URL carries the file's content hash (?v=...), so it can never go stale
                        headers.append((b"cache-control", b"public, max-age=31536000, immutable"))
                    else:
                        headers.append((b"cache-control", b"no-cache"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Rejects request bodies larger than max_bytes, by header and while streaming."""

    def __init__(self, app: ASGIApp, max_bytes: int, overrides: list[tuple[re.Pattern, int]] | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.overrides = overrides or []     # (POST path pattern, larger limit): e.g. encrypted chat attachments

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.max_bytes
        if scope.get("method") == "POST":
            for pattern, bigger in self.overrides:
                if pattern.match(scope["path"]):
                    limit = bigger
                    break

        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                await self._reject(send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


class StaticOnlyGzip:
    """Compress static files only. API and page responses carry secrets (CSRF tokens) next to user-controlled
    text, so compressing them would invite BREACH-style attacks; static files contain no secrets."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.gzip = GZipMiddleware(app, minimum_size=1024)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith("/static/"):
            await self.gzip(scope, receive, send)
        else:
            await self.app(scope, receive, send)
