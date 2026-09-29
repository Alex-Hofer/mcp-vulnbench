import subprocess

from fastmcp import FastMCP

from helpers import run_shell

app = FastMCP("fixture")


@app.tool  # model: fastmcp Member[FastMCP].ReturnValue.Member[tool].Argument[0].Parameter[any]
def bare(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection


@app.tool(name="exec")  # model: fastmcp Member[FastMCP].ReturnValue.Member[tool].ReturnValue.Argument[0].Parameter[any]
def called(command: str) -> str:
    return run_shell(command)


@app.resource("files://{path}")  # model: fastmcp Member[FastMCP].ReturnValue.Member[resource].ReturnValue.Argument[0].Parameter[any]
def file(path: str) -> str:
    with open(path) as handle:  # expect: py/path-injection
        return handle.read()


@app.prompt  # model: fastmcp Member[FastMCP].ReturnValue.Member[prompt].Argument[0].Parameter[any]
def bare_prompt(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection


@app.prompt()  # model: fastmcp Member[FastMCP].ReturnValue.Member[prompt].ReturnValue.Argument[0].Parameter[any]
def called_prompt(expression: str) -> str:
    return str(eval(expression))  # expect: py/code-injection
