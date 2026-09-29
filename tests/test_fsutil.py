import os
import stat

from conftest import is_read_only, windows_only
from mcpvb.fsutil import remove_tree


def test_remove_tree_removes_a_tree(tmp_path):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "file").write_text("x", encoding="utf-8")
    remove_tree(tree)
    assert not tree.exists()


@windows_only
def test_remove_tree_removes_read_only_folders_and_files(tmp_path):
    tree = tmp_path / "tree"
    (tree / "objects").mkdir(parents=True)
    (tree / "objects" / "pack").write_text("x", encoding="utf-8")
    for path in (tree / "objects" / "pack", tree / "objects", tree):
        os.chmod(path, stat.S_IREAD)
        assert is_read_only(path)
    remove_tree(tree)
    assert not tree.exists()
