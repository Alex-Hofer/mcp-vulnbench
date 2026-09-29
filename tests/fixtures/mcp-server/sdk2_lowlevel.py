import subprocess

from mcp.server import Server


async def handle_call(ctx, params):
    return subprocess.run("ping " + params.arguments["host"], shell=True)  # expect: py/command-line-injection


async def handle_read(ctx, params):
    with open(str(params.uri)) as handle:  # expect: py/path-injection
        return handle.read()


async def handle_prompt(ctx, params):
    return str(eval(params.arguments["expression"]))  # expect: py/code-injection


server = Server(
    "fixture",
    on_call_tool=handle_call,  # model: mcp.server.lowlevel.Server! Argument[on_call_tool:].Parameter[1].Member[arguments]
    on_read_resource=handle_read,  # model: mcp.server.lowlevel.Server! Argument[on_read_resource:].Parameter[1].Member[uri]
    on_get_prompt=handle_prompt,  # model: mcp.server.lowlevel.Server! Argument[on_get_prompt:].Parameter[1].Member[arguments]
)
