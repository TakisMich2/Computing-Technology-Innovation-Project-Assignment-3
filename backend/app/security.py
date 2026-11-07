"""
ASGI middleware for request IDs, privacy-conscious logging, request size limits
and security headers.

These classes use plain ASGI rather than BaseHTTPMiddleware so the size limit
can inspect the raw request stream and security headers are added to errors too.
"""

import json
import logging
import time
import uuid

logger = logging.getLogger('phishcheck')

# Keep scripts and styles on our own site, and prevent other sites from
# embedding the front end in a frame.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)

# The optional /docs page needs a looser policy because Swagger UI loads
# resources from jsDelivr and uses an inline script.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)

SECURITY_HEADERS = [
    (b'x-content-type-options', b'nosniff'),
    (b'x-frame-options', b'DENY'),
    (b'referrer-policy', b'no-referrer'),
    (b'permissions-policy', b'camera=(), microphone=(), geolocation=(), payment=(), usb=()'),
    (b'cross-origin-opener-policy', b'same-origin'),
    (b'cross-origin-resource-policy', b'same-origin'),
]


class RequestContextMiddleware:
    """Add a request ID and log each request without recording submitted URLs.

    Logs include only the method, path, status and duration. Unexpected errors
    are logged with a traceback on the server and returned as a standard JSON
    500, so clients never see internal details or a plain-text error page.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        request_id = uuid.uuid4().hex[:16]
        scope.setdefault('state', {})['request_id'] = request_id
        started = time.perf_counter()
        status = {'code': 500, 'started': False}

        async def send_with_id(message):
            if message['type'] == 'http.response.start':
                status['code'] = message['status']
                status['started'] = True
                message.setdefault('headers', []).append((b'x-request-id', request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception:
            logger.exception('Unhandled error (request_id=%s)', request_id)
            if not status['started']:
                await _send_json_error(
                    send_with_id, 500, 'internal_error',
                    'Something went wrong on our side. Please try again; if it keeps happening, quote the request ID.',
                    request_id,
                )
        finally:
            logger.info(
                '%s %s -> %s in %.1f ms (request_id=%s)',
                scope['method'], scope['path'], status['code'], (time.perf_counter() - started) * 1000, request_id,
            )


class _BodyTooLarge(Exception):
    pass


async def _send_json_error(send, status: int, code: str, message: str, request_id: str | None = None):
    error = {'code': code, 'message': message}
    if request_id:
        error['request_id'] = request_id
    body = json.dumps({'error': error}).encode()
    await send({
        'type': 'http.response.start',
        'status': status,
        'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())],
    })
    await send({'type': 'http.response.body', 'body': body})


class BodySizeLimitMiddleware:
    """Return 413 for oversized requests, even if Content-Length is missing or incorrect."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        request_id = scope.get('state', {}).get('request_id')
        message = f'The request body is too large (limit {self.max_bytes:,} bytes).'
        length = dict(scope['headers']).get(b'content-length')
        if length is not None:
            if not length.isdigit():
                return await _send_json_error(send, 400, 'bad_request', 'Invalid Content-Length header.', request_id)
            if int(length) > self.max_bytes:
                return await _send_json_error(send, 413, 'payload_too_large', message, request_id)

        received = 0
        too_large = False
        response_started = False

        async def limited_receive():
            nonlocal received, too_large
            incoming = await receive()
            if incoming['type'] == 'http.request':
                received += len(incoming.get('body', b''))
                if received > self.max_bytes:
                    too_large = True
                    raise _BodyTooLarge()
            return incoming

        async def guarded_send(outgoing):
            # FastAPI would turn a body-read exception into a 400. Once the size
            # limit is reached, replace that response with our 413 instead.
            nonlocal response_started
            if too_large:
                if outgoing['type'] == 'http.response.start' and not response_started:
                    response_started = True
                    await _send_json_error(send, 413, 'payload_too_large', message, request_id)
                return
            if outgoing['type'] == 'http.response.start':
                response_started = True
            await send(outgoing)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            if not response_started:
                await _send_json_error(send, 413, 'payload_too_large', message, request_id)


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        is_api = scope['path'].startswith('/api')
        csp = DOCS_CSP if scope['path'] == '/docs' else CSP

        async def send_with_headers(message):
            if message['type'] == 'http.response.start':
                headers = message.setdefault('headers', [])
                existing = {name.lower() for name, _ in headers}
                headers.extend(h for h in [(b'content-security-policy', csp.encode()), *SECURITY_HEADERS]
                               if h[0] not in existing)
                if is_api:
                    headers.append((b'cache-control', b'no-store'))
            await send(message)

        await self.app(scope, receive, send_with_headers)
