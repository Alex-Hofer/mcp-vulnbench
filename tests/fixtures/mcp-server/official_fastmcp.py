import subprocess
import urllib.request

from mcp.server.fastmcp import FastMCP

server = FastMCP("fixture")


@server.tool()  # model: mcp Member[server].Member[fastmcp].Member[FastMCP].ReturnValue.Member[tool].ReturnValue.Argument[0].Parameter[any]
def run(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@server.resource("notes://{name}")  # model: mcp Member[server].Member[fastmcp].Member[FastMCP].ReturnValue.Member[resource].ReturnValue.Argument[0].Parameter[any]
def note(name: str) -> str:
    with open(f"/notes/{name}") as handle:  # expect: py/path-injection
        return handle.read()


@server.prompt()  # model: mcp Member[server].Member[fastmcp].Member[FastMCP].ReturnValue.Member[prompt].ReturnValue.Argument[0].Parameter[any]
def summarize(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


def fetch(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


server.add_tool(fetch)  # model: mcp Member[server].Member[fastmcp].Member[FastMCP].ReturnValue.Member[add_tool].Argument[0].Parameter[any]
