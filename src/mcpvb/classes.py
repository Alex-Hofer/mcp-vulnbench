"""Vulnerability classes in scope and their CWE mapping."""

import re
from enum import StrEnum


class VulnClass(StrEnum):
    COMMAND_INJECTION = "command-injection"
    PATH_TRAVERSAL = "path-traversal"
    SSRF = "ssrf"
    SQL_INJECTION = "sql-injection"
    CODE_INJECTION = "code-injection"


CLASS_CWES: dict[VulnClass, frozenset[str]] = {
    VulnClass.COMMAND_INJECTION: frozenset({"CWE-78", "CWE-88"}),
    VulnClass.PATH_TRAVERSAL: frozenset({"CWE-22", "CWE-59"}),
    VulnClass.SSRF: frozenset({"CWE-918"}),
    VulnClass.SQL_INJECTION: frozenset({"CWE-89"}),
    VulnClass.CODE_INJECTION: frozenset({"CWE-94", "CWE-95"}),
}

_CWE_EXACT = re.compile(r"(?:cwe[-_ ]?)?0*(\d{1,5})", re.IGNORECASE)
_CWE_IN_TEXT = re.compile(r"cwe[-_/ ]?0*(\d{1,5})", re.IGNORECASE)


def normalize_cwe(raw: str | int) -> str | None:
    """'CWE-078', 'cwe-78', '78' or 78 -> 'CWE-78'; anything else -> None."""
    if isinstance(raw, int):
        return f"CWE-{raw}" if raw > 0 else None
    match = _CWE_EXACT.fullmatch(raw.strip())
    if not match or int(match.group(1)) == 0:
        return None
    return f"CWE-{int(match.group(1))}"


def cwes_in_text(text: str) -> set[str]:
    """All CWE references in free text, e.g. SARIF tags 'external/cwe/cwe-078' or 'CWE-22: ...'."""
    return {f"CWE-{int(number)}" for number in _CWE_IN_TEXT.findall(text) if int(number) > 0}


def class_for_cwe(cwe: str | None) -> VulnClass | None:
    for vuln_class, cwes in CLASS_CWES.items():
        if cwe in cwes:
            return vuln_class
    return None


def cwe_number(cwe: str) -> int:
    return int(cwe.removeprefix("CWE-"))
