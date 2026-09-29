import subprocess

from mcp.server import Server

server = Server("fixture")


@server.call_tool()  # model: mcp Member[server].Member[Server].ReturnValue.Member[call_tool].ReturnValue.Argument[0].Parameter[any]
async def call_tool(name: str, arguments: dict):
    return subprocess.run("ping " + arguments["host"], shell=True)  # expect: py/command-line-injection


@server.read_resource()  # model: mcp Member[server].Member[Server].ReturnValue.Member[read_resource].ReturnValue.Argument[0].Parameter[any]
async def read_resource(uri):
    with open(str(uri)) as handle:  # expect: py/path-injection
        return handle.read()


@server.get_prompt()  # model: mcp Member[server].Member[Server].ReturnValue.Member[get_prompt].ReturnValue.Argument[0].Parameter[any]
async def get_prompt(name: str, arguments: dict | None):
    return subprocess.run("echo " + arguments["text"], shell=True)  # expect: py/command-line-injection
