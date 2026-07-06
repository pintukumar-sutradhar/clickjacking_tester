from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class XFrameOptionsValue(str, Enum):
    MISSING = "missing"
    DENY = "deny"
    SAMEORIGIN = "sameorigin"
    ALLOW_FROM = "allow-from"
    INVALID = "invalid"


class FrameAncestorsValue(str, Enum):
    MISSING = "missing"
    NONE = "none"
    SELF = "self"
    WILDCARD = "wildcard"
    ALLOWED_DOMAINS = "allowed_domains"
    INVALID = "invalid"


class ProtectionVerdict(str, Enum):
    PROTECTED = "protected"
    PARTIALLY_PROTECTED = "partially_protected"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"


class XFrameOptionsResult(BaseModel):
    raw_value: Optional[str] = None
    classification: XFrameOptionsValue = XFrameOptionsValue.MISSING
    allow_from_domain: Optional[str] = None
    explanation: str = ""


class FrameAncestorsResult(BaseModel):
    raw_directive: Optional[str] = None
    classification: FrameAncestorsValue = FrameAncestorsValue.MISSING
    allowed_sources: List[str] = Field(default_factory=list)
    explanation: str = ""


class FrameProtectionReport(BaseModel):
    x_frame_options: XFrameOptionsResult
    frame_ancestors: FrameAncestorsResult
    verdict: ProtectionVerdict
    verdict_explanation: str


class TargetAnalysisResult(BaseModel):
    requested_url: str
    final_url: Optional[str] = None
    redirect_count: int = 0
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    protection: Optional[FrameProtectionReport] = None

    @property
    def reachable(self) -> bool:
        return self.error is None and self.status_code is not None


class AttackTemplateKind(str, Enum):
    STANDARD_IFRAME = "standard_iframe"
    FULLSCREEN_IFRAME = "fullscreen_iframe"
    TRANSPARENT_IFRAME = "transparent_iframe"
    HIDDEN_IFRAME = "hidden_iframe"
    OVERLAY_ATTACK = "overlay_attack"
    FAKE_BUTTON_OVERLAY = "fake_button_overlay"
    FAKE_LOGIN_OVERLAY = "fake_login_overlay"
    FAKE_POPUP = "fake_popup"
    FLOATING_IFRAME = "floating_iframe"
    MOBILE_LAYOUT = "mobile_layout"
    TABLET_LAYOUT = "tablet_layout"
    DESKTOP_LAYOUT = "desktop_layout"
    CUSTOM = "custom"


class AttackTemplate(BaseModel):
    kind: AttackTemplateKind
    name: str
    description: str
    default_opacity: float = 1.0
    default_width: str = "100%"
    default_height: str = "100%"
    viewport_width: Optional[int] = None
    viewport_height: Optional[int] = None
    uses_overlay_button: bool = False
    uses_overlay_login: bool = False
    uses_overlay_popup: bool = False
    is_custom: bool = False


class BuilderState(BaseModel):
    target_url: str = ""
    template_kind: AttackTemplateKind = AttackTemplateKind.STANDARD_IFRAME
    iframe_top: int = 0
    iframe_left: int = 0
    iframe_width: str = "100%"
    iframe_height: str = "100%"
    iframe_opacity: float = 1.0
    iframe_z_index: int = 1
    overlay_enabled: bool = False
    overlay_text: str = "Click here to claim your prize!"
    overlay_top: int = 200
    overlay_left: int = 150
    overlay_z_index: int = 2
    overlay_image_url: str = ""
    background_color: str = "#f2f2f7"
    background_image_url: str = ""
    custom_html: str = ""
    custom_css: str = ""
    custom_js: str = ""
    page_title: str = "Clickjacking Proof of Concept"

    @field_validator("iframe_opacity")
    @classmethod
    def clamp_opacity(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class ServerState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class ServerStatus(BaseModel):
    state: ServerState = ServerState.STOPPED
    port: Optional[int] = None
    host: str = "127.0.0.1"
    filename: Optional[str] = None
    message: Optional[str] = None

    @property
    def url(self) -> Optional[str]:
        if self.port is None or self.filename is None:
            return None
        return f"http://{self.host}:{self.port}/{self.filename}"


class ValidationOutcome(str, Enum):
    LOADED = "loaded"
    BLOCKED_X_FRAME_OPTIONS = "blocked_x_frame_options"
    BLOCKED_CSP_FRAME_ANCESTORS = "blocked_csp_frame_ancestors"
    BROWSER_RESTRICTION = "browser_restriction"
    NETWORK_ERROR = "network_error"
    UNKNOWN = "unknown"


class ValidationResult(BaseModel):
    outcome: ValidationOutcome
    explanation: str


class BrowserKind(str, Enum):
    CHROME = "chrome"
    FIREFOX = "firefox"
    EDGE = "edge"
    DEFAULT = "default"


class Session(BaseModel):
    name: str
    builder_state: BuilderState
    target_url: str = ""
    port: int = 8765
