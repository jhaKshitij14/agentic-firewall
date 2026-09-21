"""Demo MCP servers.

1. DemoToolServer: an in-process stand-in for an MCP server. The tests and the red-team benchmark
   use it because attacks need to *mutate* the server (rug pulls, poisoned output) and check
   whether a malicious call ever reached it (`call_log`).
2. build_mcp_server(): the same demo tools exposed as a real MCP server via the official SDK
   (run `python -m app.mcp.server` for a stdio server the firewall can proxy to).

All tool handlers are SIMULATED. Nothing here touches the filesystem, network, or a shell.
"""
from typing import Any, Callable

from app.models.requests import ToolDefinition, ToolResponse

Handler = Callable[..., str]


# --------------------------------------------------------------------------------------------
# Demo tool handlers (typed, because the real MCP SDK derives the input schema from signatures)
# --------------------------------------------------------------------------------------------
_PRICES = {"RELIANCE": 2950.55, "TCS": 4120.10, "INFY": 1830.75, "HDFCBANK": 1675.20}


def search_news(query: str) -> str:
    return f"[simulated] Top headlines for '{query}': (1) Markets close flat. (2) Analysts expect a steady quarter."


def get_stock_price(symbol: str) -> str:
    price = _PRICES.get(symbol.upper())
    if price is None:
        return f"[simulated] unknown symbol {symbol}"
    return f"[simulated] {symbol.upper()}: INR {price:.2f}"


def write_file(path: str, content: str) -> str:
    return f"[simulated] wrote {len(content)} characters to {path}"


def delete_file(path: str) -> str:
    return f"[simulated] deleted {path}"


def execute_trade(symbol: str, quantity: int, side: str = "BUY") -> str:
    return f"[simulated] {side} {quantity} x {symbol.upper()} executed"


def execute_command(command: str) -> str:
    return f"[simulated] would run: {command}"


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


_STR = {"type": "string"}

DEMO_TOOLS: list[tuple[ToolDefinition, Handler]] = [
    (
        ToolDefinition(
            name="search_news",
            description="Search recent news headlines for a query.",
            input_schema=_schema({"query": _STR}, ["query"]),
        ),
        search_news,
    ),
    (
        ToolDefinition(
            name="get_stock_price",
            description="Get the latest price for a stock symbol.",
            input_schema=_schema({"symbol": _STR}, ["symbol"]),
        ),
        get_stock_price,
    ),
    (
        ToolDefinition(
            name="write_file",
            description="Write text content to a file.",
            input_schema=_schema({"path": _STR, "content": _STR}, ["path", "content"]),
        ),
        write_file,
    ),
    (
        ToolDefinition(
            name="delete_file",
            description="Delete a file.",
            input_schema=_schema({"path": _STR}, ["path"]),
        ),
        delete_file,
    ),
    (
        ToolDefinition(
            name="execute_trade",
            description="Place a market order for a stock.",
            input_schema=_schema(
                {"symbol": _STR, "quantity": {"type": "integer"}, "side": _STR}, ["symbol", "quantity"]
            ),
        ),
        execute_trade,
    ),
    (
        ToolDefinition(
            name="execute_command",
            description="Run a shell command.",
            input_schema=_schema({"command": _STR}, ["command"]),
        ),
        execute_command,
    ),
]


# --------------------------------------------------------------------------------------------
# In-process fake MCP server (used by tests and the benchmark)
# --------------------------------------------------------------------------------------------
class DemoToolServer:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._handlers: dict[str, Handler] = {}
        self.call_log: list[tuple[str, dict[str, Any]]] = []

    def register(self, definition: ToolDefinition, handler: Handler) -> None:
        self._tools[definition.name] = definition
        self._handlers[definition.name] = handler

    def mutate(self, name: str, **changes: Any) -> None:
        """Simulate a server changing a tool definition after it was approved (rug pull)."""
        self._tools[name] = self._tools[name].model_copy(update=changes)

    def set_handler(self, name: str, handler: Handler) -> None:
        self._handlers[name] = handler

    def calls_to(self, name: str) -> int:
        return sum(1 for n, _ in self.call_log if n == name)

    async def list_tools(self) -> list[ToolDefinition]:
        return [t.model_copy(deep=True) for t in self._tools.values()]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResponse:
        self.call_log.append((name, dict(arguments)))
        handler = self._handlers.get(name)
        if handler is None:
            return ToolResponse(text="error: unknown tool", is_error=True)
        try:
            return ToolResponse(text=str(handler(**arguments)))
        except Exception:
            return ToolResponse(text="error: tool execution failed", is_error=True)


def build_demo_server() -> DemoToolServer:
    server = DemoToolServer()
    for definition, handler in DEMO_TOOLS:
        server.register(definition.model_copy(deep=True), handler)
    return server


# --------------------------------------------------------------------------------------------
# Real MCP server (official SDK). Works with mcp 1.x (FastMCP) and mcp 2.x (MCPServer).
# --------------------------------------------------------------------------------------------
def build_mcp_server():
    try:
        from mcp.server.mcpserver import MCPServer as _Server  # mcp >= 2
    except ImportError:
        from mcp.server.fastmcp import FastMCP as _Server  # mcp 1.x

    server = _Server("demo-finance-tools")
    for definition, handler in DEMO_TOOLS:
        server.add_tool(handler, name=definition.name, description=definition.description)
    return server


if __name__ == "__main__":
    build_mcp_server().run()  # stdio transport
