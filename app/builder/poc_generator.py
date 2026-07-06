from __future__ import annotations
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from app.core.attack_templates import get_template
from app.core.models import AttackTemplateKind, BuilderState

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(disabled_extensions=("j2",), default=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _overlay_kind(state: BuilderState) -> str:
    template = get_template(state.template_kind)
    if template.uses_overlay_login:
        return "login"
    if template.uses_overlay_button:
        return "button"
    if template.uses_overlay_popup:
        return "popup"
    if state.overlay_enabled:
        return "button"
    return "none"


def generate_poc_html(state: BuilderState) -> str:
    template = _env.get_template("poc_base.html.j2")
    overlay_kind = _overlay_kind(state)
    return template.render(
        page_title=state.page_title or "Clickjacking Proof of Concept",
        target_url=state.target_url,
        iframe_top=state.iframe_top,
        iframe_left=state.iframe_left,
        iframe_width=state.iframe_width,
        iframe_height=state.iframe_height,
        iframe_opacity=state.iframe_opacity,
        iframe_z_index=state.iframe_z_index,
        overlay_enabled=state.overlay_enabled or overlay_kind != "none",
        overlay_kind=overlay_kind,
        overlay_text=state.overlay_text,
        overlay_top=state.overlay_top,
        overlay_left=state.overlay_left,
        overlay_z_index=state.overlay_z_index,
        overlay_image_url=state.overlay_image_url,
        background_color=state.background_color,
        background_image_url=state.background_image_url,
        custom_html=state.custom_html,
        custom_css=state.custom_css,
        custom_js=state.custom_js,
        viewport_width=get_template(state.template_kind).viewport_width,
        viewport_height=get_template(state.template_kind).viewport_height,
        is_custom=state.template_kind == AttackTemplateKind.CUSTOM,
    )


def filename_for_target(target_url: str) -> str:
    import urllib.parse

    parsed = urllib.parse.urlparse(
        target_url if "://" in target_url else f"http://{target_url}"
    )
    host = (parsed.hostname or "target").replace(":", "_")
    return f"{host}_clickjacking_poc.html"
