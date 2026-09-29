"""Toy MCP server, fixed version (test fixture of mcp-vulnbench)."""

import re
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("toy-server")
NOTES_DIR = Path("/srv/notes")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host once and return the output."""
    if not HOST_RE.fullmatch(host):
        raise ValueError("invalid host name")
    completed = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return completed.stdout


@mcp.tool()
def read_note(name: str) -> str:
    """Return the content of a note."""
    target = (NOTES_DIR / name).resolve()
    if not target.is_relative_to(NOTES_DIR.resolve()):
        raise ValueError("note path escapes the notes directory")
    return target.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run()
