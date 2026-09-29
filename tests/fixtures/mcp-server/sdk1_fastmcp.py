import functools
import subprocess
import urllib.request

from pydantic import BaseModel

from mcp.server.fastmcp import Context
from mcp.server.fastmcp import FastMCP  # type: mcp.server.fastmcp.FastMCP! mcp Member[server].Member[fastmcp].Member[FastMCP]
from mcp.server.fastmcp.server import FastMCP as ModuleFastMCP  # type: mcp.server.fastmcp.FastMCP! mcp Member[server].Member[fastmcp].Member[server].Member[FastMCP]

server = FastMCP("fixture")  # type: mcp.server.fastmcp.FastMCP mcp.server.fastmcp.FastMCP! Instance
other = ModuleFastMCP("fixture")


@server.tool()  # model: mcp.server.fastmcp.FastMCP Member[tool].ReturnValue.Argument[0].Parameter[any]
def run(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@other.resource("notes://{name}")  # model: mcp.server.fastmcp.FastMCP Member[resource].ReturnValue.Argument[0].Parameter[any]
def note(name: str) -> str:
    with open(f"/notes/{name}") as handle:  # expect: py/path-injection
        return handle.read()


@server.prompt()  # model: mcp.server.fastmcp.FastMCP Member[prompt].ReturnValue.Argument[0].Parameter[any]
def summarize(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


def fetch(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


other.add_tool(fn=fetch)  # model: mcp.server.fastmcp.FastMCP Member[add_tool].Argument[0,fn:].Parameter[any]


def register(app: FastMCP) -> None:
    """Instances also reach helper functions through annotated parameters."""

    @app.tool()
    def remove(path: str) -> str:
        return subprocess.check_output("rm " + path, shell=True, text=True)  # expect: py/command-line-injection


class Service:
    """An instance stored in an attribute."""

    def __init__(self) -> None:
        self.mcp = FastMCP("fixture")
        self.register()

    def register(self) -> None:
        @self.mcp.tool()
        def lookup(host: str) -> str:
            return subprocess.check_output("nslookup " + host, shell=True, text=True)  # expect: py/command-line-injection


def logged(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


@server.tool()
@logged
def wrapped(command: str) -> str:
    # the model marks the wrapper's *args/**kwargs; CodeQL does not follow func(*args, **kwargs)
    return subprocess.check_output(command, shell=True, text=True)  # known-miss: py/command-line-injection


class Request(BaseModel):
    command: str


@server.tool()
def typed(request: Request) -> str:
    return subprocess.check_output(request.command, shell=True, text=True)  # known-miss: py/command-line-injection


@server.tool()
def forward(ctx: Context) -> str:
    target = ctx.request_context.request.headers["x-target"]
    return urllib.request.urlopen(target).read().decode()  # known-miss: py/full-ssrf
