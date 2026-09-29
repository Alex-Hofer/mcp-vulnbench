import subprocess

from mcp.server import Server  # type: mcp.server.lowlevel.Server! mcp Member[server].Member[Server]
from mcp.server.lowlevel import Server as LowLevelServer  # type: mcp.server.lowlevel.Server! mcp Member[server].Member[lowlevel].Member[Server]
from mcp.server.lowlevel.server import Server as ModuleServer  # type: mcp.server.lowlevel.Server! mcp Member[server].Member[lowlevel].Member[server].Member[Server]

first = Server("fixture")  # type: mcp.server.lowlevel.Server mcp.server.lowlevel.Server! Instance
second = LowLevelServer("fixture")
third = ModuleServer("fixture")


@first.call_tool()  # model: mcp.server.lowlevel.Server Member[call_tool].ReturnValue.Argument[0].Parameter[any]
async def call_tool(name: str, arguments: dict):
    return subprocess.run("ping " + arguments["host"], shell=True)  # expect: py/command-line-injection


@second.read_resource()  # model: mcp.server.lowlevel.Server Member[read_resource].ReturnValue.Argument[0].Parameter[any]
async def read_resource(uri):
    with open(str(uri)) as handle:  # expect: py/path-injection
        return handle.read()


@third.get_prompt()  # model: mcp.server.lowlevel.Server Member[get_prompt].ReturnValue.Argument[0].Parameter[any]
async def get_prompt(name: str, arguments: dict | None):
    return subprocess.run("echo " + arguments["text"], shell=True)  # expect: py/command-line-injection
