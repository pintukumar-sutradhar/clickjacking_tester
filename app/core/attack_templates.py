from __future__ import annotations
from typing import Dict, List
from app.core.models import AttackTemplate, AttackTemplateKind, BuilderState

_TEMPLATES: Dict[AttackTemplateKind, AttackTemplate] = {
    AttackTemplateKind.STANDARD_IFRAME: AttackTemplate(
        kind=AttackTemplateKind.STANDARD_IFRAME,
        name="Standard Iframe",
        description="A plain, fully visible iframe embedding the target page as-is.",
        default_opacity=1.0,
        default_width="100%",
        default_height="100%",
    ),
    AttackTemplateKind.FULLSCREEN_IFRAME: AttackTemplate(
        kind=AttackTemplateKind.FULLSCREEN_IFRAME,
        name="Fullscreen Iframe",
        description="Iframe stretched to fill the entire viewport with no margins.",
        default_opacity=1.0,
        default_width="100vw",
        default_height="100vh",
    ),
    AttackTemplateKind.TRANSPARENT_IFRAME: AttackTemplate(
        kind=AttackTemplateKind.TRANSPARENT_IFRAME,
        name="Transparent Iframe",
        description="Low-opacity iframe layered above decoy content, classic clickjacking pattern.",
        default_opacity=0.15,
        default_width="100%",
        default_height="100%",
    ),
    AttackTemplateKind.HIDDEN_IFRAME: AttackTemplate(
        kind=AttackTemplateKind.HIDDEN_IFRAME,
        name="Hidden Iframe",
        description="Iframe reduced to a near-invisible sliver positioned over a decoy control.",
        default_opacity=0.02,
        default_width="200px",
        default_height="60px",
    ),
    AttackTemplateKind.OVERLAY_ATTACK: AttackTemplate(
        kind=AttackTemplateKind.OVERLAY_ATTACK,
        name="Overlay Attack",
        description="Decoy content overlaid on top of a semi-transparent framed target.",
        default_opacity=0.3,
        default_width="100%",
        default_height="100%",
    ),
    AttackTemplateKind.FAKE_BUTTON_OVERLAY: AttackTemplate(
        kind=AttackTemplateKind.FAKE_BUTTON_OVERLAY,
        name="Fake Button Overlay",
        description="A decoy button positioned exactly above a sensitive control in the framed target.",
        default_opacity=0.05,
        default_width="100%",
        default_height="100%",
        uses_overlay_button=True,
    ),
    AttackTemplateKind.FAKE_LOGIN_OVERLAY: AttackTemplate(
        kind=AttackTemplateKind.FAKE_LOGIN_OVERLAY,
        name="Fake Login Overlay",
        description="A fake login form decoy overlaid above the transparent framed target.",
        default_opacity=0.05,
        default_width="100%",
        default_height="100%",
        uses_overlay_login=True,
    ),
    AttackTemplateKind.FAKE_POPUP: AttackTemplate(
        kind=AttackTemplateKind.FAKE_POPUP,
        name="Fake Popup",
        description="A modal-style fake popup decoy layered above the framed target.",
        default_opacity=0.1,
        default_width="100%",
        default_height="100%",
        uses_overlay_popup=True,
    ),
    AttackTemplateKind.FLOATING_IFRAME: AttackTemplate(
        kind=AttackTemplateKind.FLOATING_IFRAME,
        name="Floating Iframe",
        description="A small floating/draggable-looking iframe panel positioned away from the page edge.",
        default_opacity=0.9,
        default_width="480px",
        default_height="360px",
    ),
    AttackTemplateKind.MOBILE_LAYOUT: AttackTemplate(
        kind=AttackTemplateKind.MOBILE_LAYOUT,
        name="Mobile Layout",
        description="Simulates a mobile viewport (375x667) for testing mobile-targeted clickjacking.",
        default_opacity=1.0,
        default_width="100%",
        default_height="100%",
        viewport_width=375,
        viewport_height=667,
    ),
    AttackTemplateKind.TABLET_LAYOUT: AttackTemplate(
        kind=AttackTemplateKind.TABLET_LAYOUT,
        name="Tablet Layout",
        description="Simulates a tablet viewport (768x1024) for testing tablet-targeted clickjacking.",
        default_opacity=1.0,
        default_width="100%",
        default_height="100%",
        viewport_width=768,
        viewport_height=1024,
    ),
    AttackTemplateKind.DESKTOP_LAYOUT: AttackTemplate(
        kind=AttackTemplateKind.DESKTOP_LAYOUT,
        name="Desktop Layout",
        description="Simulates a standard desktop viewport (1440x900).",
        default_opacity=1.0,
        default_width="100%",
        default_height="100%",
        viewport_width=1440,
        viewport_height=900,
    ),
    AttackTemplateKind.CUSTOM: AttackTemplate(
        kind=AttackTemplateKind.CUSTOM,
        name="Custom Template",
        description="A blank canvas -- fully define your own HTML, CSS and JavaScript.",
        default_opacity=1.0,
        default_width="100%",
        default_height="100%",
        is_custom=True,
    ),
}


def get_template(kind: AttackTemplateKind) -> AttackTemplate:
    return _TEMPLATES[kind]


def list_templates() -> List[AttackTemplate]:
    return list(_TEMPLATES.values())


def apply_template_to_state(
    state: BuilderState, kind: AttackTemplateKind
) -> BuilderState:
    template = get_template(kind)
    updated = state.model_copy(deep=True)
    updated.template_kind = kind
    updated.iframe_opacity = template.default_opacity
    updated.iframe_width = template.default_width
    updated.iframe_height = template.default_height
    updated.overlay_enabled = (
        template.uses_overlay_button
        or template.uses_overlay_login
        or template.uses_overlay_popup
    )
    return updated
