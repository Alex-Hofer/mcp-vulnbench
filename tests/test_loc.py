from mcpvb.loc import count_kloc
from mcpvb.schema import Language


def test_count_kloc_counts_non_blank_lines_of_the_language(tmp_path):
    (tmp_path / "app.py").write_text("a = 1\n\nb = 2\nc = 3\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\n" * 50, encoding="utf-8")
    (tmp_path / "web.ts").write_text("const a = 1;\n", encoding="utf-8")
    assert count_kloc(tmp_path, Language.PYTHON) == 0.003
    assert count_kloc(tmp_path, Language.TYPESCRIPT) == 0.001
