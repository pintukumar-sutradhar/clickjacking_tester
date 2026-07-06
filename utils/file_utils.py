from __future__ import annotations
import platform
import subprocess
import webbrowser
from pathlib import Path


def save_html_file(directory: Path, filename: str, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path


def open_file_in_os(path: Path) -> None:
    system = platform.system()
    try:
        if system == "Windows":
            import os

            os.startfile(str(path))
        elif system == "Darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError:
        webbrowser.open(f"file://{path.resolve()}")
