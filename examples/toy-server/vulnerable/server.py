"""Toy MCP server with two deliberately vulnerable tools (test fixture of mcp-vulnbench)."""

import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("toy-server")
NOTES_DIR = Path("/srv/notes")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host once and return the output."""
    completed = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return completed.stdout


@mcp.tool()
def read_note(name: str) -> str:
    """Return the content of a note."""
    with open(NOTES_DIR / name, encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    mcp.run()
