from __future__ import annotations
import platform
import shutil
import subprocess
import webbrowser
from typing import List, Optional
from app.core.models import BrowserKind

_CANDIDATES = {
    BrowserKind.CHROME: {
        "Darwin": ["/Applications/Google Chrome.app"],
        "Windows": ["chrome", "chrome.exe"],
        "Linux": [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
        ],
    },
    BrowserKind.FIREFOX: {
        "Darwin": ["/Applications/Firefox.app"],
        "Windows": ["firefox", "firefox.exe"],
        "Linux": ["firefox"],
    },
    BrowserKind.EDGE: {
        "Darwin": ["/Applications/Microsoft Edge.app"],
        "Windows": ["msedge", "msedge.exe"],
        "Linux": ["microsoft-edge", "microsoft-edge-stable"],
    },
}


def _find_executable(browser: BrowserKind) -> Optional[str]:
    system = platform.system()
    candidates = _CANDIDATES.get(browser, {}).get(system, [])
    for candidate in candidates:
        if system == "Darwin" and candidate.endswith(".app"):
            import os

            if os.path.isdir(candidate):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    return None


def launch_browser(url: str, browser: BrowserKind = BrowserKind.DEFAULT) -> bool:
    if browser == BrowserKind.DEFAULT:
        return webbrowser.open(url, new=2)
    system = platform.system()
    executable = _find_executable(browser)
    try:
        if executable is None:
            return webbrowser.open(url, new=2)
        if system == "Darwin" and executable.endswith(".app"):
            subprocess.Popen(["open", "-a", executable, url])
        else:
            subprocess.Popen([executable, url])
        return True
    except OSError:
        return webbrowser.open(url, new=2)


def launch_multiple_browsers(
    url: str, browsers: List[BrowserKind]
) -> List[BrowserKind]:
    launched: List[BrowserKind] = []
    for browser in browsers:
        if launch_browser(url, browser):
            launched.append(browser)
    return launched
