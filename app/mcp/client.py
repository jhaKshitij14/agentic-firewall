"""Upstream connectors: how the firewall talks to the MCP server it protects.

`Upstream` is the seam. The firewall only needs list_tools() and call_tool(), so it works the
same against the in-process demo server (tests, benchmark) and a real MCP server over stdio.
"""
from __future__ import annotations

import json
import re
from contextlib import AsyncExitStack
from typing import Any, Mapping, Protocol, Sequence

from app.mcp.server import DemoToolServer
from app.models.requests import ToolDefinition, ToolResponse


class Upstream(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def list_tools(self) -> list[ToolDefinition]: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResponse: ...


class InProcessUpstream:
    """Wraps a DemoToolServer."""

    def __init__(self, server: DemoToolServer) -> None:
        self.server = server

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def list_tools(self) -> list[ToolDefinition]:
        return await self.server.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResponse:
        return await self.server.call_tool(name, arguments)


# --------------------------------------------------------------------------------------------
# Real MCP server over stdio via the official Python SDK (mcp 1.x and 2.x)
# --------------------------------------------------------------------------------------------
_CAMEL = re.compile(r"(?<=[a-z0-9])([A-Z])")


def _snake(key: str) -> str:
    return _CAMEL.sub(lambda m: "_" + m.group(1).lower(), key)


def _snake_keys(d: Mapping[str, Any]) -> dict[str, Any]:
    return {_snake(k): v for k, v in d.items()}


def tool_to_definition(tool: Any) -> ToolDefinition:
    """Convert an SDK Tool (any supported SDK version) into our ToolDefinition.

    Keys are normalised to snake_case so the same server yields the same fingerprint whichever
    SDK version is installed. Every server-declared field is kept so nothing escapes hashing.
    """
    data = _snake_keys(tool.model_dump(mode="json", exclude_none=True))
    name = data.pop("name")
    description = data.pop("description", "") or ""
    input_schema = data.pop("input_schema", None) or {}
    annotations = _snake_keys(data.pop("annotations", None) or {})
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema,
        annotations=annotations,
        extras=data,
    )


def result_to_response(result: Any) -> ToolResponse:
    """Flatten an SDK CallToolResult into text the scanner can inspect.

    Non-text blocks (images, audio, binary resources) cannot be inspected, so they are replaced
    with a placeholder rather than passed through unscanned.
    """
    if not hasattr(result, "content"):
        return ToolResponse(text="[unsupported upstream result type]", is_error=True)
    is_error = bool(getattr(result, "isError", getattr(result, "is_error", False)))
    parts: list[str] = []
    for block in result.content or []:
        btype = getattr(block, "type", "unknown")
        if btype == "text":
            parts.append(block.text)
        elif btype == "resource":
            text = getattr(block.resource, "text", None)
            parts.append(text if isinstance(text, str) else "[binary resource omitted by firewall]")
        else:
            parts.append(f"[{btype} content omitted by firewall]")
    if not parts:
        structured = getattr(result, "structuredContent", getattr(result, "structured_content", None))
        if structured is not None:
            parts.append(json.dumps(structured, ensure_ascii=False))
    return ToolResponse(text="\n".join(parts), is_error=is_error)


class StdioMCPUpstream:
    """Spawns an MCP server as a subprocess and keeps one session open.

    start() and stop() must run in the same asyncio task (FastAPI's lifespan does this).
    """

    def __init__(
        self,
        command: str,
        args: Sequence[str] = (),
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        self._command = command
        self._args = list(args)
        self._env = env
        self._cwd = cwd
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def start(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=self._command, args=self._args, env=self._env, cwd=self._cwd
        )
        stack = AsyncExitStack()
        try:
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except BaseException:
            await stack.aclose()
            raise
        self._stack, self._session = stack, session

    async def stop(self) -> None:
        if self._stack is not None:
            stack, self._stack, self._session = self._stack, None, None
            await stack.aclose()

    def _require_session(self) -> Any:
        if self._session is None:
            raise RuntimeError("upstream not started")
        return self._session

    async def list_tools(self) -> list[ToolDefinition]:
        session = self._require_session()
        tools: list[ToolDefinition] = []
        cursor: str | None = None
        for _ in range(100):  # hard page cap
            result = await self._list_page(session, cursor)
            tools.extend(tool_to_definition(t) for t in result.tools)
            cursor = getattr(result, "nextCursor", getattr(result, "next_cursor", None))
            if not cursor:
                break
        return tools

    @staticmethod
    async def _list_page(session: Any, cursor: str | None) -> Any:
        if cursor is None:
            return await session.list_tools()
        try:
            from mcp import types

            return await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor))
        except TypeError:
            return await session.list_tools(cursor=cursor)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResponse:
        session = self._require_session()
        result = await session.call_tool(name, arguments)
        return result_to_response(result)
