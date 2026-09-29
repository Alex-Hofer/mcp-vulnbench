import subprocess
import urllib.request

from mcp.server import MCPServer  # type: mcp.server.mcpserver.MCPServer! mcp Member[server].Member[MCPServer]
from mcp.server.mcpserver import MCPServer as PackageMCPServer  # type: mcp.server.mcpserver.MCPServer! mcp Member[server].Member[mcpserver].Member[MCPServer]
from mcp.server.mcpserver.server import MCPServer as ModuleMCPServer  # type: mcp.server.mcpserver.MCPServer! mcp Member[server].Member[mcpserver].Member[server].Member[MCPServer]

first = MCPServer("fixture")  # type: mcp.server.mcpserver.MCPServer mcp.server.mcpserver.MCPServer! Instance
second = PackageMCPServer("fixture")
third = ModuleMCPServer("fixture")


@first.tool()  # model: mcp.server.mcpserver.MCPServer Member[tool].ReturnValue.Argument[0].Parameter[any]
def run(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@second.resource("notes://{name}")  # model: mcp.server.mcpserver.MCPServer Member[resource].ReturnValue.Argument[0].Parameter[any]
def note(name: str) -> str:
    with open(f"/notes/{name}") as handle:  # expect: py/path-injection
        return handle.read()


@third.prompt()  # model: mcp.server.mcpserver.MCPServer Member[prompt].ReturnValue.Argument[0].Parameter[any]
def summarize(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


def fetch(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


first.add_tool(fetch)  # model: mcp.server.mcpserver.MCPServer Member[add_tool].Argument[0,fn:].Parameter[any]
