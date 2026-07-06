from __future__ import annotations
import json
from pathlib import Path
from pydantic import BaseModel
from app.core.models import AttackTemplateKind, BrowserKind

SETTINGS_PATH = Path(__file__).resolve().parent / "settings.json"


class AppTheme(str):
    LIGHT = "light"
    DARK = "dark"


class Settings(BaseModel):
    default_browser: BrowserKind = BrowserKind.DEFAULT
    default_port: int = 8765
    default_attack_template: AttackTemplateKind = AttackTemplateKind.STANDARD_IFRAME
    theme: str = "dark"

    def save(self) -> None:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls) -> "Settings":
        if SETTINGS_PATH.exists():
            try:
                data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                return cls.model_validate(data)
            except (json.JSONDecodeError, ValueError):
                pass
        return cls()

    def reset_to_defaults(self) -> "Settings":
        defaults = Settings()
        self.default_browser = defaults.default_browser
        self.default_port = defaults.default_port
        self.default_attack_template = defaults.default_attack_template
        self.theme = defaults.theme
        return self
