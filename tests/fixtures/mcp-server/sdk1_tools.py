import subprocess

from sdk1_app import app


@app.tool()
def ping(host: str) -> str:
    """A tool registered on an instance imported from another module."""
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)  # expect: py/command-line-injection
