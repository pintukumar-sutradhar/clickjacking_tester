from __future__ import annotations
import json
from pathlib import Path
from typing import List
from app.core.models import BuilderState, Session

SESSIONS_DIR = Path(__file__).resolve().parent.parent.parent / "sessions"


def _safe_filename(name: str) -> str:
    cleaned = "".join(
        (c if c.isalnum() or c in ("-", "_", " ") else "_" for c in name)
    ).strip()
    return (cleaned or "session") + ".json"


def ensure_sessions_dir() -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def list_sessions() -> List[str]:
    ensure_sessions_dir()
    return sorted((p.stem for p in SESSIONS_DIR.glob("*.json")))


def save_session(session: Session) -> Path:
    ensure_sessions_dir()
    path = SESSIONS_DIR / _safe_filename(session.name)
    path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_session(name: str) -> Session:
    path = SESSIONS_DIR / _safe_filename(name)
    data = json.loads(path.read_text(encoding="utf-8"))
    return Session.model_validate(data)


def delete_session(name: str) -> bool:
    path = SESSIONS_DIR / _safe_filename(name)
    if path.exists():
        path.unlink()
        return True
    return False


def new_session(name: str = "Untitled Session") -> Session:
    return Session(name=name, builder_state=BuilderState(), target_url="", port=8765)
