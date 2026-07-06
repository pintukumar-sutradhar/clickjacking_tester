from __future__ import annotations
import flet as ft

BG_DARK = "#0b0e14"
PANEL_DARK = "#12151d"
PANEL_DARK_ALT = "#171b25"
BORDER_DARK = "#242a38"
ACCENT = "#7c5cff"
ACCENT_SOFT = "#7c5cff22"
DANGER = "#ff5f6d"
DANGER_SOFT = "#ff5f6d22"
WARNING = "#ffb454"
WARNING_SOFT = "#ffb45422"
SUCCESS = "#3ddc97"
SUCCESS_SOFT = "#3ddc9722"
TEXT_PRIMARY = "#f2f3f7"
TEXT_MUTED = "#8b93a7"
BG_LIGHT = "#f4f5fa"
PANEL_LIGHT = "#ffffff"
PANEL_LIGHT_ALT = "#eef0f7"
BORDER_LIGHT = "#dfe2ec"


def verdict_color(verdict: str) -> str:
    mapping = {
        "protected": SUCCESS,
        "partially_protected": WARNING,
        "vulnerable": DANGER,
        "unknown": TEXT_MUTED,
    }
    return mapping.get(verdict, TEXT_MUTED)


def verdict_icon(verdict: str):
    mapping = {
        "protected": ft.Icons.CHECK_CIRCLE,
        "partially_protected": ft.Icons.WARNING_AMBER,
        "vulnerable": ft.Icons.ERROR_OUTLINE,
        "unknown": ft.Icons.HELP_OUTLINE,
    }
    return mapping.get(verdict, ft.Icons.HELP_OUTLINE)


def simple_verdict_summary(verdict: str) -> str:
    mapping = {
        "protected": "This website is protected against clickjacking. It cannot be secretly placed inside another website's page.",
        "partially_protected": "This website has partial protection. It blocks most outside websites from framing it, but not all.",
        "vulnerable": "This website is NOT protected. Any other website could secretly place it inside their page and trick visitors into clicking on it.",
        "unknown": "We couldn't determine the protection status for this website.",
    }
    return mapping.get(verdict, mapping["unknown"])


def section_card(
    content: ft.Control, *, bgcolor: str = PANEL_DARK, border_color: str = BORDER_DARK
) -> ft.Container:
    return ft.Container(
        content=content,
        bgcolor=bgcolor,
        border=ft.Border.all(1, border_color),
        border_radius=14,
        padding=18,
    )


def section_title(text: str, icon) -> ft.Row:
    return ft.Row(
        [
            ft.Icon(icon, size=18, color=ACCENT),
            ft.Text(text, size=13, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
        ],
        spacing=8,
    )
