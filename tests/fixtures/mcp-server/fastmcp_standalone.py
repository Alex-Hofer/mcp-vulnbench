import subprocess
import urllib.request

from fastmcp import FastMCP  # type: fastmcp.FastMCP! fastmcp Member[FastMCP]
from fastmcp.server import FastMCP as ServerFastMCP  # type: fastmcp.FastMCP! fastmcp Member[server].Member[FastMCP]
from fastmcp.server.server import FastMCP as ModuleFastMCP  # type: fastmcp.FastMCP! fastmcp Member[server].Member[server].Member[FastMCP]
from fastmcp.server.dependencies import get_http_headers, get_http_request
from fastmcp.tools import FunctionTool  # type: fastmcp.tools.Tool! fastmcp Member[tools].Member[FunctionTool]
from fastmcp.tools import Tool  # type: fastmcp.tools.Tool! fastmcp Member[tools].Member[Tool]
from fastmcp.tools import tool
from fastmcp.tools.base import Tool as BaseTool  # type: fastmcp.tools.Tool! fastmcp Member[tools].Member[base].Member[Tool]
from fastmcp.tools.function_tool import FunctionTool as ModuleFunctionTool  # type: fastmcp.tools.Tool! fastmcp Member[tools].Member[function_tool].Member[FunctionTool]

from helpers import run_shell

app = FastMCP("fixture")  # type: fastmcp.FastMCP fastmcp.FastMCP! Instance
server_app = ServerFastMCP("fixture")
module_app = ModuleFastMCP("fixture")


@app.tool  # model: fastmcp.FastMCP Member[tool].Argument[0,name_or_fn:].Parameter[any]
def bare(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@server_app.tool(name="exec")  # model: fastmcp.FastMCP Member[tool].ReturnValue.Argument[0].Parameter[any]
def called(command: str) -> str:
    return run_shell(command)


@module_app.resource("files://{path}")  # model: fastmcp.FastMCP Member[resource].ReturnValue.Argument[0].Parameter[any]
def file(path: str) -> str:
    with open(path) as handle:  # expect: py/path-injection
        return handle.read()


@app.prompt  # model: fastmcp.FastMCP Member[prompt].Argument[0,name_or_fn:].Parameter[any]
def bare_prompt(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


@app.prompt()  # model: fastmcp.FastMCP Member[prompt].ReturnValue.Argument[0].Parameter[any]
def called_prompt(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


def added(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


app.add_tool(added)  # model: fastmcp.FastMCP Member[add_tool].Argument[0,tool:].Parameter[any]


def added_prompt(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


app.add_prompt(added_prompt)  # model: fastmcp.FastMCP Member[add_prompt].Argument[0,prompt:].Parameter[any]


def via_tool(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


def via_function_tool(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


def via_base_tool(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


def via_module_function_tool(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()  # expect: py/full-ssrf


Tool.from_function(via_tool)  # model: fastmcp.tools.Tool! Member[from_function].Argument[0,fn:].Parameter[any]
FunctionTool.from_function(via_function_tool)
BaseTool.from_function(fn=via_base_tool)
ModuleFunctionTool.from_function(via_module_function_tool)


@tool  # model: fastmcp Member[tools].Member[tool].Argument[0,name_or_fn:].Parameter[any]
def standalone(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@tool()  # model: fastmcp Member[tools].Member[tool].ReturnValue.Argument[0].Parameter[any]
def standalone_called(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@app.tool
def header_forward() -> str:
    target = get_http_headers()["x-target"]  # model: fastmcp Member[server].Member[dependencies].Member[get_http_headers].ReturnValue
    return urllib.request.urlopen(target).read().decode()  # expect: py/full-ssrf


@app.tool
def header_command() -> str:
    command = get_http_request().headers["x-command"]  # model: fastmcp Member[server].Member[dependencies].Member[get_http_request].ReturnValue.Member[headers]
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection
