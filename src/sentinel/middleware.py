from __future__ import annotations
from typing import Callable
from contextvars import ContextVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from .taint import taint_recursive

# global variable to store taint flow stack
taint_flow: ContextVar[list] = ContextVar("taint_flow", default=[])


class SentinelMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that taints JSON bodies."""

    def __init__(self, app, tags=("untrusted", "http")):
        super().__init__(app)
        self.tags = tags

    async def dispatch(self, request: Request, call_next: Callable):
        # Initialize taint flow for this request
        flow = ["http_request"]
        taint_flow.set(flow)

        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                data = await request.json()
                request.state.tainted_json = taint_recursive(data, *self.tags)
                flow.append("middleware:json_parsing")
                taint_flow.set(flow)
            except Exception:
                request.state.tainted_json = None
        else:
            request.state.tainted_json = None

        response = await call_next(request)
        return response
