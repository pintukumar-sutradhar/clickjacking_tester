from __future__ import annotations
from pathlib import Path
from typing import List, Optional
from app.builder.poc_generator import filename_for_target, generate_poc_html
from app.core.analyzer import analyze_target
from app.core.attack_templates import apply_template_to_state, list_templates
from app.core.models import (
    AttackTemplate,
    AttackTemplateKind,
    BrowserKind,
    BuilderState,
    ServerStatus,
    Session,
    TargetAnalysisResult,
    ValidationResult,
)
from app.core.sessions import (
    delete_session,
    list_sessions,
    load_session,
    new_session,
    save_session,
)
from app.preview.validator import validate_poc
from app.server.browser_launcher import launch_browser, launch_multiple_browsers
from app.server.local_server import (
    PoCServer,
    find_random_available_port,
    is_port_available,
)
from config.settings import Settings
from utils.file_utils import open_file_in_os, save_html_file
from utils.url_utils import apply_custom_port, normalize_url

GENERATED_DIR = Path(__file__).resolve().parent.parent / "generated"


class AppController:

    def __init__(self) -> None:
        self.settings: Settings = Settings.load()
        self.builder_state: BuilderState = BuilderState(
            template_kind=self.settings.default_attack_template
        )
        self.server = PoCServer()
        self.last_analysis: Optional[TargetAnalysisResult] = None
        self.last_validation: Optional[ValidationResult] = None
        self.last_saved_path: Optional[Path] = None

    async def analyze(
        self, raw_url: str, custom_port: Optional[int] = None
    ) -> TargetAnalysisResult:
        url = normalize_url(raw_url)
        if custom_port:
            url = apply_custom_port(url, custom_port)
        result = await analyze_target(url)
        self.last_analysis = result
        self.builder_state.target_url = result.final_url or url
        return result

    def templates(self) -> List[AttackTemplate]:
        return list_templates()

    def apply_template(self, kind: AttackTemplateKind) -> BuilderState:
        self.builder_state = apply_template_to_state(self.builder_state, kind)
        return self.builder_state

    def generate_html(self) -> str:
        return generate_poc_html(self.builder_state)

    def poc_filename(self) -> str:
        return filename_for_target(self.builder_state.target_url or "target")

    def save_poc(self, directory: Optional[Path] = None) -> Path:
        html = self.generate_html()
        filename = self.poc_filename()
        target_dir = directory or GENERATED_DIR
        path = save_html_file(target_dir, filename, html)
        self.last_saved_path = path
        return path

    def open_saved_file(self) -> None:
        if self.last_saved_path is not None:
            open_file_in_os(self.last_saved_path)

    def reset_builder(self) -> BuilderState:
        target_url = self.builder_state.target_url
        self.builder_state = BuilderState(target_url=target_url)
        return self.builder_state

    def start_server(self, port: Optional[int] = None) -> ServerStatus:
        html = self.generate_html()
        filename = self.poc_filename()
        self.server.set_content(filename, html)
        use_port = port or self.settings.default_port
        return self.server.start(port=use_port)

    def start_server_on_random_port(self) -> ServerStatus:
        html = self.generate_html()
        filename = self.poc_filename()
        self.server.set_content(filename, html)
        return self.server.start(port=self.random_port())

    def stop_server(self) -> ServerStatus:
        return self.server.stop()

    def restart_server(self, port: Optional[int] = None) -> ServerStatus:
        html = self.generate_html()
        filename = self.poc_filename()
        self.server.set_content(filename, html)
        return self.server.restart(port=port)

    def refresh_server_content(self) -> None:
        html = self.generate_html()
        filename = self.poc_filename()
        self.server.set_content(filename, html)

    def random_port(self) -> int:
        return find_random_available_port()

    def port_available(self, port: int) -> bool:
        return is_port_available(port)

    def launch_in_browser(self, browser: BrowserKind = BrowserKind.DEFAULT) -> bool:
        url = self.server.status.url
        if not url:
            return False
        return launch_browser(url, browser)

    def launch_in_multiple_browsers(
        self, browsers: List[BrowserKind]
    ) -> List[BrowserKind]:
        url = self.server.status.url
        if not url:
            return []
        return launch_multiple_browsers(url, browsers)

    def validate(self) -> Optional[ValidationResult]:
        if self.last_analysis is None:
            return None
        self.last_validation = validate_poc(self.last_analysis)
        return self.last_validation

    def list_sessions(self) -> List[str]:
        return list_sessions()

    def save_session(self, name: str) -> Path:
        session = Session(
            name=name,
            builder_state=self.builder_state,
            target_url=self.builder_state.target_url,
            port=self.server.status.port or self.settings.default_port,
        )
        return save_session(session)

    def load_session(self, name: str) -> Session:
        session = load_session(name)
        self.builder_state = session.builder_state
        return session

    def delete_session(self, name: str) -> bool:
        return delete_session(name)

    def new_session(self) -> BuilderState:
        session = new_session()
        self.builder_state = session.builder_state
        self.last_analysis = None
        self.last_validation = None
        return self.builder_state

    def save_settings(self) -> None:
        self.settings.save()

    def reset_settings(self) -> Settings:
        self.settings.reset_to_defaults()
        self.settings.save()
        return self.settings
