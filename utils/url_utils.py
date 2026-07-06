from __future__ import annotations
import urllib.parse


def normalize_url(raw_url: str, default_scheme: str = "http") -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if "://" not in raw_url:
        return f"{default_scheme}://{raw_url}"
    return raw_url


def apply_custom_port(url: str, port: int | None) -> str:
    if not port:
        return url
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    netloc = f"{hostname}:{port}"
    if parsed.username:
        auth = parsed.username + (f":{parsed.password}" if parsed.password else "")
        netloc = f"{auth}@{netloc}"
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))


def hostname_of(url: str) -> str:
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname or "target"
