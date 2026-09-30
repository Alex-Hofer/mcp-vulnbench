import urllib.request
from pathlib import Path

from fastmcp.server.auth import AuthProvider  # type: fastmcp.server.auth.AuthProvider! fastmcp Member[server].Member[auth].Member[AuthProvider]
from fastmcp.server.auth import TokenVerifier  # type: fastmcp.server.auth.TokenVerifier! fastmcp Member[server].Member[auth].Member[TokenVerifier]
from fastmcp.server.auth.auth import AuthProvider as ModuleAuthProvider  # type: fastmcp.server.auth.AuthProvider! fastmcp Member[server].Member[auth].Member[auth].Member[AuthProvider]
from fastmcp.server.auth.auth import TokenVerifier as ModuleTokenVerifier  # type: fastmcp.server.auth.TokenVerifier! fastmcp Member[server].Member[auth].Member[auth].Member[TokenVerifier]
from fastmcp.server.dependencies import get_access_token
from mcp.server.auth.middleware.auth_context import get_access_token as sdk_get_access_token
from mcp.server.auth.provider import TokenVerifier as SdkTokenVerifier  # type: mcp.server.auth.provider.TokenVerifier! mcp Member[server].Member[auth].Member[provider].Member[TokenVerifier]

# The bearer token of the Authorization header reaches token verifiers and the access-token helpers.


class SessionFileVerifier(TokenVerifier):  # model: fastmcp.server.auth.TokenVerifier! Subclass.Member[verify_token].Parameter[0,token:]
    async def verify_token(self, token: str):
        return (Path("/sessions") / f"{token}.session").is_file()  # expect: py/path-injection


class ModuleVerifier(ModuleTokenVerifier):
    async def verify_token(self, token: str):
        with open(f"/sessions/{token}") as handle:  # expect: py/path-injection
            return handle.read()


class Provider(AuthProvider):  # model: fastmcp.server.auth.AuthProvider! Subclass.Member[verify_token].Parameter[0,token:]
    async def verify_token(self, token: str):
        with open(f"/tokens/{token}") as handle:  # expect: py/path-injection
            return handle.read()


class ModuleProvider(ModuleAuthProvider):
    async def verify_token(self, token: str):
        with open(f"/tokens/{token}") as handle:  # expect: py/path-injection
            return handle.read()


class SdkVerifier(SdkTokenVerifier):  # model: mcp.server.auth.provider.TokenVerifier! Subclass.Member[verify_token].Parameter[0,token:]
    async def verify_token(self, token: str):
        with open(f"/tokens/{token}") as handle:  # expect: py/path-injection
            return handle.read()


def session_of_request() -> str:
    token = get_access_token().token  # model: fastmcp Member[server].Member[dependencies].Member[get_access_token].ReturnValue.Member[token]
    with open(f"/sessions/{token}") as handle:  # expect: py/path-injection
        return handle.read()


def introspect() -> str:
    token = sdk_get_access_token().token  # model: mcp Member[server].Member[auth].Member[middleware].Member[auth_context].Member[get_access_token].ReturnValue.Member[token]
    return urllib.request.urlopen(token).read().decode()  # expect: py/full-ssrf
