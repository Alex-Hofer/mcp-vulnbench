import pytest

from mcpvb.classes import VulnClass, class_for_cwe, cwes_in_text, normalize_cwe


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("CWE-078", "CWE-78"),
        ("cwe-78", "CWE-78"),
        ("78", "CWE-78"),
        (78, "CWE-78"),
        (" CWE-22 ", "CWE-22"),
        ("0", None),
        ("SQLi", None),
        ("", None),
    ],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_cwes_in_text_understands_sarif_tag_styles():
    assert cwes_in_text("external/cwe/cwe-078") == {"CWE-78"}
    assert cwes_in_text("CWE-22: Improper Limitation of a Pathname") == {"CWE-22"}
    assert cwes_in_text("security, OWASP-A03") == set()
    assert cwes_in_text("CWE-89 and cwe_918") == {"CWE-89", "CWE-918"}


@pytest.mark.parametrize(
    "cwe, expected",
    [
        ("CWE-78", VulnClass.COMMAND_INJECTION),
        ("CWE-88", VulnClass.COMMAND_INJECTION),
        ("CWE-59", VulnClass.PATH_TRAVERSAL),
        ("CWE-918", VulnClass.SSRF),
        ("CWE-89", VulnClass.SQL_INJECTION),
        ("CWE-95", VulnClass.CODE_INJECTION),
        ("CWE-703", None),
        (None, None),
    ],
)
def test_class_for_cwe(cwe, expected):
    assert class_for_cwe(cwe) == expected
