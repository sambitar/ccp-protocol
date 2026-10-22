"""FastAPI integration for CCP providers.

The adapter only parses the HTTP envelope, resolves the sender key, and
delegates to :class:`ccp.runtime.Runtime`. It never decides authorization.
"""

import inspect
from dataclasses import asdict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ..errors import AUTHORIZED, CONFIRMATION_REQUIRED

_STATUS = {
    AUTHORIZED: 200,
    CONFIRMATION_REQUIRED: 200,
    "invalid_request": 400,
    "unauthenticated": 403,
    "no_matching_grant": 403,
}


def _decision_body(decision):
    return {
        name: value
        for name, value in asdict(decision).items()
        if value is not None
    }


def _error(status, code):
    return JSONResponse({"outcome": code, "error": code},
                        status_code=status)


def signal_endpoint(runtime, key_resolver):
    """Build an async FastAPI endpoint that accepts signed signals.

    ``key_resolver`` receives the request and returns the sender's
    :class:`ccp.crypto.VerifyingKey` (or an awaitable of one), or ``None``
    when the sender is unknown.
    """

    async def endpoint(request: Request):
        try:
            body = await request.json()
        except Exception:
            return _error(400, "invalid_request")
        if not isinstance(body, dict) or not isinstance(body.get("signal"), str):
            return _error(400, "invalid_request")

        try:
            key = key_resolver(request)
            if inspect.isawaitable(key):
                key = await key
        except Exception:
            key = None
        if key is None:
            return _error(401, "unauthenticated")

        try:
            decision = runtime.submit(body["signal"], key)
        except Exception:
            return _error(500, "outcome_unknown")

        return JSONResponse(
            _decision_body(decision),
            status_code=_STATUS.get(decision.outcome, 409),
        )

    return endpoint


def provider_router(runtime, key_resolver, *, path="/ccp"):
    """An ``APIRouter`` with the provider's signal endpoint."""
    router = APIRouter()
    router.add_api_route(path, signal_endpoint(runtime, key_resolver),
                         methods=["POST"])
    return router


def manifest_endpoint(manifest_wire):
    """Build an endpoint that serves the signed manifest verbatim."""

    async def endpoint(_request: Request):
        return Response(content=manifest_wire, media_type="application/json")

    return endpoint


def manifest_router(manifest_wire, *, path="/manifest"):
    """An ``APIRouter`` with the provider's manifest endpoint."""
    router = APIRouter()
    router.add_api_route(path, manifest_endpoint(manifest_wire),
                         methods=["GET"])
    return router
