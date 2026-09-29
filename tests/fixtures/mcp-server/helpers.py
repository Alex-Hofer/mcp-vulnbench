import subprocess


def run_shell(command):
    return subprocess.check_output(command, shell=True, text=True)  # expect: py/command-line-injection
