"""Deleting the harness's own folders, also where Windows marks entries read-only."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


def remove_tree(path: Path) -> None:
    """shutil.rmtree that also deletes read-only entries.

    Windows refuses to delete read-only entries (WinError 5). Backup clients such as Google Drive
    for desktop mark every folder they back up read-only, and git marks its object files read-only.
    The attribute is cleared and the deletion retried; other errors are raised unchanged.
    """

    def clear_read_only(func, target, exc):
        if not getattr(os.lstat(target), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_READONLY:
            raise exc
        os.chmod(target, stat.S_IWRITE)
        func(target)

    shutil.rmtree(path, onexc=clear_read_only)
