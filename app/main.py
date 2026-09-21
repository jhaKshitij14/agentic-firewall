"""HTTP layer (FastAPI) + CLI. All security logic lives in app/firewall/; this file only translates.

Run:
    python -m app.main create-user alice analyst     # prints an API key once
    python -m app.main create-user root admin
    python -m app.main serve                         # or: uvicorn app.main:create_app --factory

Endpoints (session id goes in the `X-Session-Id` header):
    POST /api/session        {user_id, api_key}      -> session_id
    GET  /api/tools                                   -> tools you may use (approved + permitted)
    POST /api/tools/approve  {tools?: [names]}        -> pin current tool definitions   [manager]
    POST /api/request        {tool, arguments}        -> firewall decision (+ response if allowed)
    GET  /api/policies                                -> active policy                  [manager]
    GET  /api/logs?limit=50                           -> audit trail                    [manager]
"""
from __future__ import annotations

import argparse
import math
import os
import secrets
import shlex
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.firewall.authentication import AuthError, Authenticator
from app.firewall.authorization import PermissionDenied
from app.firewall.gateway import Firewall
from app.firewall.rate_limiter import RateLimitExceeded
from app.mcp.client import InProcessUpstream, StdioMCPUpstream, Upstream
from app.mcp.server import build_demo_server
from app.models.events import Stage
from app.models.policies import Policy, load_policy
from app.models.requests import ToolRequest
from app.storage.database import Database

DEFAULT_POLICY_PATH = Path(__file__).parent / "config" / "policies.yaml"
DEFAULT_DB_PATH = "firewall.db"

_STATUS_BY_STAGE = {
    Stage.AUTHENTICATION: 401,
    Stage.RATE_LIMIT: 429,
    Stage.VALIDATION: 400,
    Stage.AUTHORIZATION: 403,
    Stage.INTEGRITY: 403,
    Stage.INPUT_SCAN: 403,
    Stage.OUTPUT_SCAN: 403,
    Stage.CIRCUIT_BREAKER: 503,
    Stage.UPSTREAM: 502,
    Stage.INTERNAL: 500,
}


class LoginBody(BaseModel):
    user_id: str
    api_key: str


class RequestBody(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ApproveBody(BaseModel):
    tools: list[str] | None = None


def _retry_headers(retry_after: float | None) -> dict[str, str]:
    return {"Retry-After": str(max(1, math.ceil(retry_after)))} if retry_after else {}


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AuthError):
        return HTTPException(401, str(exc))
    if isinstance(exc, RateLimitExceeded):
        return HTTPException(429, "rate limit exceeded", headers=_retry_headers(exc.retry_after))
    if isinstance(exc, PermissionDenied):
        return HTTPException(403, str(exc))
    raise exc


def _upstream_from_env() -> Upstream:
    kind = os.environ.get("FIREWALL_UPSTREAM", "demo").lower()
    if kind == "demo":
        return InProcessUpstream(build_demo_server())
    if kind == "stdio":
        command = os.environ.get("FIREWALL_UPSTREAM_COMMAND", sys.executable)
        args = shlex.split(os.environ.get("FIREWALL_UPSTREAM_ARGS", "-m app.mcp.server"))
        return StdioMCPUpstream(command, args)
    raise ValueError(f"FIREWALL_UPSTREAM must be 'demo' or 'stdio', got {kind!r}")


def create_app(
    *,
    policy: Policy | None = None,
    db: Database | None = None,
    upstream: Upstream | None = None,
    firewall: Firewall | None = None,
) -> FastAPI:
    if firewall is None:
        policy = policy or load_policy(os.environ.get("FIREWALL_POLICY_PATH", DEFAULT_POLICY_PATH))
        db = db or Database(os.environ.get("FIREWALL_DB_PATH", DEFAULT_DB_PATH))
        firewall = Firewall(policy, db, upstream or _upstream_from_env())
    fw = firewall

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await fw.upstream.start()
        try:
            yield
        finally:
            await fw.upstream.stop()

    app = FastAPI(title="Agentic Firewall", version="2.0", lifespan=lifespan)
    app.state.firewall = fw

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/session")
    async def create_session(body: LoginBody, request: Request) -> dict[str, Any]:
        client = request.client.host if request.client else "unknown"
        try:
            session_id, session = fw.login(body.user_id, body.api_key, client_key=client)
        except (AuthError, RateLimitExceeded) as exc:
            raise _http_error(exc)
        return {
            "session_id": session_id,
            "user_id": session.user_id,
            "role": session.role,
            "expires_at": session.expires_at,
        }

    @app.get("/api/tools")
    async def list_tools(x_session_id: str | None = Header(default=None)) -> list[dict[str, Any]]:
        try:
            tools = await fw.list_tools(x_session_id or "")
        except (AuthError, RateLimitExceeded) as exc:
            raise _http_error(exc)
        return [t.model_dump(mode="json") for t in tools]

    @app.post("/api/tools/approve")
    async def approve_tools(body: ApproveBody, x_session_id: str | None = Header(default=None)):
        try:
            session = fw.require_manager(x_session_id or "")
            outcomes = await fw.approve_tools(session, body.tools)
        except (AuthError, RateLimitExceeded, PermissionDenied) as exc:
            raise _http_error(exc)
        return [o.model_dump(mode="json") for o in outcomes]

    @app.post("/api/request")
    async def tool_request(body: RequestBody, x_session_id: str | None = Header(default=None)):
        result = await fw.handle(
            ToolRequest(session_id=x_session_id or "", tool=body.tool, arguments=body.arguments)
        )
        status = 200 if result.allowed else _STATUS_BY_STAGE.get(result.stage, 403)
        return JSONResponse(
            status_code=status,
            content=result.model_dump(mode="json"),
            headers=_retry_headers(result.retry_after),
        )

    @app.get("/api/policies")
    async def get_policies(x_session_id: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            fw.require_manager(x_session_id or "")
        except (AuthError, RateLimitExceeded, PermissionDenied) as exc:
            raise _http_error(exc)
        return fw.policy.model_dump(mode="json")

    @app.get("/api/logs")
    async def get_logs(
        limit: int = Query(50, ge=1, le=500), x_session_id: str | None = Header(default=None)
    ) -> list[dict[str, Any]]:
        try:
            fw.require_manager(x_session_id or "")
        except (AuthError, RateLimitExceeded, PermissionDenied) as exc:
            raise _http_error(exc)
        return [e.model_dump(mode="json") for e in fw.audit.recent(limit)]

    return app


# ------------------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------------------
def _cmd_create_user(args: argparse.Namespace) -> int:
    policy = load_policy(os.environ.get("FIREWALL_POLICY_PATH", DEFAULT_POLICY_PATH))
    if args.role not in policy.roles:
        print(f"error: role {args.role!r} is not defined in the policy ({', '.join(policy.roles)})", file=sys.stderr)
        return 2
    db = Database(os.environ.get("FIREWALL_DB_PATH", DEFAULT_DB_PATH))
    api_key = secrets.token_urlsafe(32)
    try:
        Authenticator(db).register_user(args.user_id, args.role, api_key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"user:    {args.user_id}\nrole:    {args.role}\napi_key: {api_key}\n(store this key now; it cannot be shown again)")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("app.main:create_app", factory=True, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.main")
    sub = parser.add_subparsers(dest="command", required=True)
    p_user = sub.add_parser("create-user", help="register a user and print a generated API key")
    p_user.add_argument("user_id")
    p_user.add_argument("role")
    p_user.set_defaults(func=_cmd_create_user)
    p_serve = sub.add_parser("serve", help="run the HTTP gateway")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=_cmd_serve)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
