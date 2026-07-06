from __future__ import annotations
import html as html_lib
from typing import Optional
import flet as ft
from app.controller import AppController
from app.core.attack_templates import get_template
from app.core.models import (
    AttackTemplateKind,
    BrowserKind,
    ServerState,
    ValidationOutcome,
)
from app.ui import theme as th

VIEWPORT_PRESETS = {"Desktop": (1280, 800), "Tablet": (768, 1024), "Mobile": (375, 667)}


class ClickjackingTesterApp:

    def __init__(self, page: ft.Page) -> None:
        self.page = page
        self.controller = AppController()
        self.preview_zoom = 1.0
        self.preview_device = "Desktop"
        self.clipboard = ft.Clipboard()
        self.page.services.append(self.clipboard)
        self._build_controls()
        self._layout()

    def _toast(self, message: str, *, color: str = th.ACCENT) -> None:
        snack = ft.SnackBar(
            content=ft.Text(message, color="#ffffff"),
            bgcolor=color,
            duration=ft.Duration(milliseconds=2800),
        )
        self.page.show_dialog(snack)

    def _show_dialog(self, dialog: ft.AlertDialog) -> None:
        self.page.show_dialog(dialog)

    def _close_dialog(self, dialog: ft.AlertDialog) -> None:
        dialog.open = False
        dialog.update()

    def _run_async(self, handler, *args, **kwargs) -> None:
        self.page.run_task(handler, *args, **kwargs)

    def _build_controls(self) -> None:
        page = self.page
        page.title = "Clickjacking Tester"
        page.bgcolor = th.BG_DARK
        page.padding = 0
        page.theme_mode = ft.ThemeMode.DARK
        page.window.width = 1180
        page.window.height = 920
        page.window.min_width = 480
        page.window.min_height = 700
        page.scroll = ft.ScrollMode.AUTO
        self.url_field = ft.TextField(
            hint_text="example.com",
            label="Website address",
            border_color=th.BORDER_DARK,
            focused_border_color=th.ACCENT,
            bgcolor=th.PANEL_DARK_ALT,
            color=th.TEXT_PRIMARY,
            height=56,
            text_size=16,
            content_padding=ft.Padding.symmetric(horizontal=16, vertical=14),
            expand=True,
            on_submit=self._on_analyze_click,
        )
        self.check_btn = ft.ElevatedButton(
            "Check Website",
            icon=ft.Icons.SEARCH,
            bgcolor=th.ACCENT,
            color="#ffffff",
            height=56,
            style=ft.ButtonStyle(
                text_style=ft.TextStyle(size=16, weight=ft.FontWeight.W_600)
            ),
            on_click=self._on_analyze_click,
        )
        self.check_progress = ft.ProgressRing(
            width=18, height=18, stroke_width=2, visible=False
        )
        self.result_icon = ft.Icon(ft.Icons.HELP_OUTLINE, size=34, color=th.TEXT_MUTED)
        self.result_title = ft.Text(
            "No website checked yet",
            size=17,
            weight=ft.FontWeight.W_700,
            color=th.TEXT_PRIMARY,
        )
        self.result_summary = ft.Text(
            'Enter a website address above and click "Check Website" to find out if it can be tricked with a clickjacking attack.',
            size=13,
            color=th.TEXT_MUTED,
        )
        self.result_banner = ft.Container(
            content=ft.Row(
                [
                    self.result_icon,
                    ft.Column(
                        [self.result_title, self.result_summary], spacing=4, expand=True
                    ),
                ],
                spacing=14,
                vertical_alignment=ft.CrossAxisAlignment.START,
            ),
            bgcolor=th.PANEL_DARK,
            border=ft.Border.all(1, th.BORDER_DARK),
            border_radius=14,
            padding=18,
        )
        self.final_url_text = ft.Text(
            "--", size=12, color=th.TEXT_MUTED, selectable=True
        )
        self.redirect_text = ft.Text("--", size=12, color=th.TEXT_MUTED)
        self.status_code_text = ft.Text("--", size=12, color=th.TEXT_MUTED)
        self.response_time_text = ft.Text("--", size=12, color=th.TEXT_MUTED)
        self.xfo_badge = self._badge("X-Frame-Options: --", th.TEXT_MUTED)
        self.xfo_detail = ft.Text(
            "Run a check to inspect this header.", size=12, color=th.TEXT_MUTED
        )
        self.fa_badge = self._badge("frame-ancestors: --", th.TEXT_MUTED)
        self.fa_detail = ft.Text(
            "Run a check to inspect the CSP frame-ancestors rule.",
            size=12,
            color=th.TEXT_MUTED,
        )
        self.technical_details = ft.ExpansionTile(
            title=ft.Text("Show technical details", size=13, color=th.TEXT_MUTED),
            leading=ft.Icon(ft.Icons.CODE, size=18, color=th.TEXT_MUTED),
            controls=[
                ft.Container(
                    padding=ft.Padding.only(top=8, bottom=4),
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    self._stat_chip(
                                        "Final address", self.final_url_text
                                    ),
                                    self._stat_chip("Redirects", self.redirect_text),
                                    self._stat_chip(
                                        "Status code", self.status_code_text
                                    ),
                                    self._stat_chip(
                                        "Response time", self.response_time_text
                                    ),
                                ],
                                spacing=24,
                                wrap=True,
                            ),
                            ft.Divider(color=th.BORDER_DARK, height=20),
                            self.xfo_badge,
                            self.xfo_detail,
                            ft.Divider(color=th.BORDER_DARK, height=20),
                            self.fa_badge,
                            self.fa_detail,
                        ],
                        spacing=8,
                    ),
                )
            ],
        )
        self.demo_status_badge = self._badge("Demo: not running", th.TEXT_MUTED)
        self.demo_url_text = ft.Text("", size=12, color=th.TEXT_MUTED, selectable=True)
        self.demo_btn = ft.ElevatedButton(
            "Create & Open Demo Page",
            icon=ft.Icons.PLAY_CIRCLE_FILLED,
            bgcolor=th.SUCCESS,
            color="#04120c",
            height=52,
            on_click=self._on_quick_demo,
        )
        self.stop_demo_btn = ft.OutlinedButton(
            "Stop Demo", icon=ft.Icons.STOP_CIRCLE, on_click=self._on_stop_server
        )
        self.template_dropdown = ft.Dropdown(
            value=AttackTemplateKind.STANDARD_IFRAME.value,
            options=[
                ft.dropdown.Option(t.kind.value, t.name)
                for t in self.controller.templates()
            ],
            bgcolor=th.PANEL_DARK_ALT,
            border_color=th.BORDER_DARK,
            focused_border_color=th.ACCENT,
            color=th.TEXT_PRIMARY,
            on_select=self._on_template_change,
            content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        )
        self.template_description = ft.Text(
            get_template(AttackTemplateKind.STANDARD_IFRAME).description,
            size=12,
            color=th.TEXT_MUTED,
        )
        self.opacity_slider = ft.Slider(
            min=0,
            max=1,
            value=1.0,
            divisions=20,
            label="{value}",
            active_color=th.ACCENT,
            on_change=self._on_builder_change,
        )
        self.zindex_field = self._number_field(
            "1", width=90, on_change=self._on_builder_change
        )
        self.top_field = self._number_field(
            "0", width=90, on_change=self._on_builder_change
        )
        self.left_field = self._number_field(
            "0", width=90, on_change=self._on_builder_change
        )
        self.width_field = self._text_field(
            "100%", width=110, on_change=self._on_builder_change
        )
        self.height_field = self._text_field(
            "100%", width=110, on_change=self._on_builder_change
        )
        self.overlay_switch = ft.Switch(
            value=False, active_color=th.ACCENT, on_change=self._on_builder_change
        )
        self.overlay_text_field = self._text_field(
            "Click here to claim your prize!",
            width=None,
            on_change=self._on_builder_change,
        )
        self.overlay_top_field = self._number_field(
            "200", width=90, on_change=self._on_builder_change
        )
        self.overlay_left_field = self._number_field(
            "150", width=90, on_change=self._on_builder_change
        )
        self.overlay_zindex_field = self._number_field(
            "2", width=90, on_change=self._on_builder_change
        )
        self.overlay_image_field = self._text_field(
            "Overlay image address (optional)",
            width=None,
            on_change=self._on_builder_change,
        )
        self.bgcolor_field = self._text_field(
            "#f2f2f7", width=140, on_change=self._on_builder_change
        )
        self.bgimage_field = self._text_field(
            "Background image address (optional)",
            width=None,
            on_change=self._on_builder_change,
        )
        self.custom_html_field = self._code_field(
            "<!-- Extra HTML injected into the page -->"
        )
        self.custom_css_field = self._code_field("/* Extra CSS rules */")
        self.custom_js_field = self._code_field("// Extra JavaScript")
        self.builder_tabs = ft.Tabs(
            length=4,
            selected_index=0,
            animation_duration=ft.Duration(milliseconds=180),
            content=ft.Column(
                [
                    ft.TabBar(
                        tabs=[
                            ft.Tab(label="Position & Size"),
                            ft.Tab(label="Decoy Overlay"),
                            ft.Tab(label="Background"),
                            ft.Tab(label="Custom Code"),
                        ],
                        label_color=th.ACCENT,
                        unselected_label_color=th.TEXT_MUTED,
                        indicator_color=th.ACCENT,
                    ),
                    ft.Container(
                        height=380,
                        content=ft.TabBarView(
                            controls=[
                                self._build_layout_tab(),
                                self._build_overlay_tab(),
                                self._build_background_tab(),
                                self._build_custom_tab(),
                            ]
                        ),
                    ),
                ]
            ),
        )
        self.preview_frame = ft.Container(
            content=ft.Column(
                [
                    ft.Icon(ft.Icons.PREVIEW, size=32, color=th.TEXT_MUTED),
                    ft.Text(
                        "Check a website and create a demo to preview it here.",
                        size=12,
                        color=th.TEXT_MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=8,
            ),
            bgcolor="#ffffff",
            border_radius=10,
            alignment=ft.Alignment.CENTER,
            width=VIEWPORT_PRESETS["Desktop"][0] * 0.4,
            height=VIEWPORT_PRESETS["Desktop"][1] * 0.4,
        )
        self.preview_wrapper = ft.Container(
            content=self.preview_frame, alignment=ft.Alignment.CENTER, padding=12
        )
        self.device_selector = ft.SegmentedButton(
            segments=[
                ft.Segment(
                    value="Desktop",
                    label=ft.Text("Desktop"),
                    icon=ft.Icon(ft.Icons.DESKTOP_WINDOWS),
                ),
                ft.Segment(
                    value="Tablet",
                    label=ft.Text("Tablet"),
                    icon=ft.Icon(ft.Icons.TABLET_MAC),
                ),
                ft.Segment(
                    value="Mobile",
                    label=ft.Text("Mobile"),
                    icon=ft.Icon(ft.Icons.PHONE_IPHONE),
                ),
            ],
            selected=["Desktop"],
            on_change=self._on_device_change,
        )
        self.zoom_text = ft.Text("100%", size=12, color=th.TEXT_MUTED)
        self.port_field = self._number_field("8765", width=110)
        self.server_status_badge = self._badge("Demo server: stopped", th.TEXT_MUTED)
        self.server_url_text = ft.Text(
            "--", size=12, color=th.TEXT_MUTED, selectable=True
        )
        self.browser_chrome_cb = ft.Checkbox(
            label="Chrome", value=True, active_color=th.ACCENT
        )
        self.browser_firefox_cb = ft.Checkbox(
            label="Firefox", value=False, active_color=th.ACCENT
        )
        self.browser_edge_cb = ft.Checkbox(
            label="Edge", value=False, active_color=th.ACCENT
        )
        self.browser_default_cb = ft.Checkbox(
            label="System default", value=False, active_color=th.ACCENT
        )
        self.validation_badge = self._badge("Result: not checked", th.TEXT_MUTED)
        self.validation_detail = ft.Text(
            "Check a website first, then validate to see the expected demo outcome.",
            size=12,
            color=th.TEXT_MUTED,
        )
        self.generated_code_view = ft.TextField(
            value="",
            multiline=True,
            min_lines=10,
            max_lines=18,
            read_only=True,
            text_style=ft.TextStyle(
                font_family="monospace", size=11, color=th.TEXT_PRIMARY
            ),
            bgcolor="#0a0d13",
            border_color=th.BORDER_DARK,
        )
        self.session_name_field = self._text_field("Name for this test", width=200)
        self.session_dropdown = ft.Dropdown(
            hint_text="Saved tests",
            options=[ft.dropdown.Option(s) for s in self.controller.list_sessions()],
            bgcolor=th.PANEL_DARK_ALT,
            border_color=th.BORDER_DARK,
            color=th.TEXT_PRIMARY,
            width=220,
            content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        )
        self.status_strip_text = ft.Text("Ready.", size=12, color=th.TEXT_MUTED)

    def _badge(self, text: str, color: str, big: bool = False) -> ft.Container:
        return ft.Container(
            content=ft.Text(
                text, size=13 if big else 11, weight=ft.FontWeight.W_600, color=color
            ),
            bgcolor=color + "22" if len(color) == 7 else th.PANEL_DARK_ALT,
            border=ft.Border.all(1, color),
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        )

    def _set_badge(self, badge: ft.Container, text: str, color: str) -> None:
        badge.content.value = text
        badge.content.color = color
        badge.bgcolor = color + "22"
        badge.border = ft.Border.all(1, color)

    def _text_field(
        self, hint: str, width: Optional[int], on_change=None
    ) -> ft.TextField:
        return ft.TextField(
            hint_text=hint,
            width=width,
            bgcolor=th.PANEL_DARK_ALT,
            border_color=th.BORDER_DARK,
            focused_border_color=th.ACCENT,
            color=th.TEXT_PRIMARY,
            content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
            on_change=on_change,
        )

    def _number_field(self, hint: str, width: int, on_change=None) -> ft.TextField:
        return ft.TextField(
            hint_text=hint,
            width=width,
            keyboard_type=ft.KeyboardType.NUMBER,
            bgcolor=th.PANEL_DARK_ALT,
            border_color=th.BORDER_DARK,
            focused_border_color=th.ACCENT,
            color=th.TEXT_PRIMARY,
            content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
            on_change=on_change,
        )

    def _code_field(self, hint: str) -> ft.TextField:
        return ft.TextField(
            hint_text=hint,
            multiline=True,
            min_lines=4,
            max_lines=8,
            bgcolor="#0a0d13",
            border_color=th.BORDER_DARK,
            focused_border_color=th.ACCENT,
            color=th.TEXT_PRIMARY,
            text_style=ft.TextStyle(font_family="monospace", size=12),
            content_padding=ft.Padding.all(10),
            on_change=self._on_builder_change,
        )

    def _stat_chip(self, label: str, value_control: ft.Text) -> ft.Column:
        return ft.Column(
            [ft.Text(label, size=10, color=th.TEXT_MUTED), value_control], spacing=2
        )

    def _build_layout_tab(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.only(top=12),
            content=ft.Column(
                [
                    ft.Text(
                        "Controls how the target website's frame is positioned, sized and how see-through it is.",
                        size=11,
                        color=th.TEXT_MUTED,
                    ),
                    ft.Row(
                        [
                            ft.Text(
                                "See-through", size=12, color=th.TEXT_MUTED, width=80
                            ),
                            self.opacity_slider,
                        ],
                        expand=True,
                    ),
                    ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.Text("Top (px)", size=11, color=th.TEXT_MUTED),
                                    self.top_field,
                                ],
                                spacing=4,
                            ),
                            ft.Column(
                                [
                                    ft.Text("Left (px)", size=11, color=th.TEXT_MUTED),
                                    self.left_field,
                                ],
                                spacing=4,
                            ),
                            ft.Column(
                                [
                                    ft.Text(
                                        "Layer order", size=11, color=th.TEXT_MUTED
                                    ),
                                    self.zindex_field,
                                ],
                                spacing=4,
                            ),
                        ],
                        spacing=14,
                        wrap=True,
                    ),
                    ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.Text("Width", size=11, color=th.TEXT_MUTED),
                                    self.width_field,
                                ],
                                spacing=4,
                            ),
                            ft.Column(
                                [
                                    ft.Text("Height", size=11, color=th.TEXT_MUTED),
                                    self.height_field,
                                ],
                                spacing=4,
                            ),
                        ],
                        spacing=14,
                        wrap=True,
                    ),
                ],
                spacing=14,
                scroll=ft.ScrollMode.AUTO,
            ),
        )

    def _build_overlay_tab(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.only(top=12),
            content=ft.Column(
                [
                    ft.Text(
                        "A decoy button, login box, or popup shown on top of the hidden website to lure clicks.",
                        size=11,
                        color=th.TEXT_MUTED,
                    ),
                    ft.Row(
                        [
                            ft.Text("Show decoy", size=12, color=th.TEXT_MUTED),
                            self.overlay_switch,
                        ]
                    ),
                    self.overlay_text_field,
                    ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.Text("Top (px)", size=11, color=th.TEXT_MUTED),
                                    self.overlay_top_field,
                                ],
                                spacing=4,
                            ),
                            ft.Column(
                                [
                                    ft.Text("Left (px)", size=11, color=th.TEXT_MUTED),
                                    self.overlay_left_field,
                                ],
                                spacing=4,
                            ),
                            ft.Column(
                                [
                                    ft.Text(
                                        "Layer order", size=11, color=th.TEXT_MUTED
                                    ),
                                    self.overlay_zindex_field,
                                ],
                                spacing=4,
                            ),
                        ],
                        spacing=14,
                        wrap=True,
                    ),
                    self.overlay_image_field,
                ],
                spacing=12,
                scroll=ft.ScrollMode.AUTO,
            ),
        )

    def _build_background_tab(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.only(top=12),
            content=ft.Column(
                [
                    ft.Column(
                        [
                            ft.Text("Background color", size=11, color=th.TEXT_MUTED),
                            self.bgcolor_field,
                        ],
                        spacing=4,
                    ),
                    self.bgimage_field,
                ],
                spacing=12,
                scroll=ft.ScrollMode.AUTO,
            ),
        )

    def _build_custom_tab(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.only(top=12),
            content=ft.Column(
                [
                    ft.Text("Custom HTML", size=11, color=th.TEXT_MUTED),
                    self.custom_html_field,
                    ft.Text("Custom CSS", size=11, color=th.TEXT_MUTED),
                    self.custom_css_field,
                    ft.Text("Custom JavaScript", size=11, color=th.TEXT_MUTED),
                    self.custom_js_field,
                ],
                spacing=6,
                scroll=ft.ScrollMode.AUTO,
            ),
        )

    def _layout(self) -> None:
        page = self.page
        header = ft.Container(
            content=ft.Row(
                [
                    ft.Row(
                        [
                            ft.Icon(ft.Icons.SHIELD, color=th.ACCENT, size=26),
                            ft.Text(
                                "Clickjacking Tester",
                                size=19,
                                weight=ft.FontWeight.BOLD,
                                color=th.TEXT_PRIMARY,
                            ),
                        ],
                        spacing=10,
                    ),
                    ft.IconButton(
                        icon=ft.Icons.SETTINGS,
                        tooltip="Settings",
                        on_click=self._on_open_settings,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            bgcolor=th.PANEL_DARK,
            padding=ft.Padding.symmetric(horizontal=24, vertical=16),
            border=ft.Border.only(bottom=ft.BorderSide(1, th.BORDER_DARK)),
        )
        check_section = th.section_card(
            ft.Column(
                [
                    ft.Text(
                        "1. Check a website",
                        size=15,
                        weight=ft.FontWeight.W_700,
                        color=th.TEXT_PRIMARY,
                    ),
                    ft.Text(
                        "Type the address of a website you're authorized to test, then click Check Website.",
                        size=12,
                        color=th.TEXT_MUTED,
                    ),
                    ft.Row(
                        [self.url_field, self.check_progress, self.check_btn],
                        spacing=10,
                    ),
                ],
                spacing=10,
            )
        )
        result_section = th.section_card(
            ft.Column(
                [
                    ft.Text(
                        "2. Result",
                        size=15,
                        weight=ft.FontWeight.W_700,
                        color=th.TEXT_PRIMARY,
                    ),
                    self.result_banner,
                    self.technical_details,
                ],
                spacing=10,
            )
        )
        demo_section = th.section_card(
            ft.Column(
                [
                    ft.Text(
                        "3. See it in action (optional)",
                        size=15,
                        weight=ft.FontWeight.W_700,
                        color=th.TEXT_PRIMARY,
                    ),
                    ft.Text(
                        "This creates a harmless practice page that tries to hide the website inside it, and opens it in your browser -- so you can see the real effect for yourself.",
                        size=12,
                        color=th.TEXT_MUTED,
                    ),
                    ft.Row([self.demo_btn, self.stop_demo_btn], spacing=10, wrap=True),
                    ft.Row([self.demo_status_badge, self.demo_url_text], spacing=10),
                ],
                spacing=10,
            )
        )
        advanced_section = ft.ExpansionTile(
            title=ft.Text(
                "Advanced options",
                size=14,
                weight=ft.FontWeight.W_600,
                color=th.TEXT_PRIMARY,
            ),
            subtitle=ft.Text(
                "Attack style, customization, manual server control, saved tests",
                size=11,
                color=th.TEXT_MUTED,
            ),
            leading=ft.Icon(ft.Icons.TUNE, color=th.ACCENT),
            controls=[self._build_advanced_content()],
        )
        content = ft.Container(
            content=ft.Column(
                [check_section, result_section, demo_section, advanced_section],
                spacing=16,
            ),
            padding=ft.Padding.symmetric(horizontal=24, vertical=20),
            width=880,
        )
        status_strip = ft.Container(
            content=self.status_strip_text,
            bgcolor=th.PANEL_DARK,
            padding=ft.Padding.symmetric(horizontal=24, vertical=10),
            border=ft.Border.only(top=ft.BorderSide(1, th.BORDER_DARK)),
        )
        page.add(
            ft.Column(
                [
                    header,
                    ft.Row([content], alignment=ft.MainAxisAlignment.CENTER),
                    status_strip,
                ],
                spacing=0,
            )
        )

    def _build_advanced_content(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.only(top=8, bottom=4),
            content=ft.Column(
                [
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title("Attack style", ft.Icons.GRID_VIEW),
                                self.template_dropdown,
                                self.template_description,
                            ],
                            spacing=10,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title(
                                    "Customize the demo page", ft.Icons.PALETTE
                                ),
                                self.builder_tabs,
                            ],
                            spacing=10,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title("Preview", ft.Icons.VISIBILITY),
                                ft.Row(
                                    [
                                        self.device_selector,
                                        ft.Row(
                                            [
                                                ft.IconButton(
                                                    icon=ft.Icons.ZOOM_OUT,
                                                    tooltip="Zoom out",
                                                    on_click=self._on_zoom_out,
                                                ),
                                                self.zoom_text,
                                                ft.IconButton(
                                                    icon=ft.Icons.ZOOM_IN,
                                                    tooltip="Zoom in",
                                                    on_click=self._on_zoom_in,
                                                ),
                                                ft.IconButton(
                                                    icon=ft.Icons.REFRESH,
                                                    tooltip="Refresh preview",
                                                    on_click=self._on_refresh_preview,
                                                ),
                                            ],
                                            spacing=0,
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    wrap=True,
                                ),
                                self.preview_wrapper,
                            ],
                            spacing=10,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title(
                                    "Demo server (manual control)", ft.Icons.DNS
                                ),
                                ft.Row(
                                    [
                                        ft.Column(
                                            [
                                                ft.Text(
                                                    "Port", size=11, color=th.TEXT_MUTED
                                                ),
                                                self.port_field,
                                            ],
                                            spacing=4,
                                        ),
                                        ft.IconButton(
                                            icon=ft.Icons.CASINO,
                                            tooltip="Pick a random available port",
                                            on_click=self._on_random_port,
                                        ),
                                    ],
                                    spacing=10,
                                ),
                                ft.Row(
                                    [
                                        ft.ElevatedButton(
                                            "Start",
                                            icon=ft.Icons.PLAY_ARROW,
                                            bgcolor=th.SUCCESS,
                                            color="#04120c",
                                            on_click=self._on_start_server,
                                        ),
                                        ft.ElevatedButton(
                                            "Stop",
                                            icon=ft.Icons.STOP_CIRCLE,
                                            bgcolor=th.DANGER,
                                            color="#210506",
                                            on_click=self._on_stop_server,
                                        ),
                                        ft.OutlinedButton(
                                            "Restart",
                                            icon=ft.Icons.RESTART_ALT,
                                            on_click=self._on_restart_server,
                                        ),
                                    ],
                                    spacing=8,
                                    wrap=True,
                                ),
                                self.server_status_badge,
                                self.server_url_text,
                            ],
                            spacing=10,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title(
                                    "Open demo in a specific browser", ft.Icons.LANGUAGE
                                ),
                                ft.Row(
                                    [self.browser_chrome_cb, self.browser_firefox_cb],
                                    spacing=4,
                                ),
                                ft.Row(
                                    [self.browser_edge_cb, self.browser_default_cb],
                                    spacing=4,
                                ),
                                ft.ElevatedButton(
                                    "Open in Selected Browsers",
                                    icon=ft.Icons.OPEN_IN_BROWSER,
                                    bgcolor=th.ACCENT,
                                    color="#ffffff",
                                    on_click=self._on_launch_browsers,
                                ),
                            ],
                            spacing=8,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title(
                                    "Result explanation", ft.Icons.FACT_CHECK
                                ),
                                self.validation_badge,
                                self.validation_detail,
                                ft.OutlinedButton(
                                    "Re-check Result",
                                    icon=ft.Icons.PLAY_CIRCLE_OUTLINE,
                                    on_click=self._on_validate,
                                ),
                            ],
                            spacing=8,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                ft.Row(
                                    [
                                        th.section_title(
                                            "Generated demo page code", ft.Icons.CODE
                                        ),
                                        ft.Row(
                                            [
                                                ft.OutlinedButton(
                                                    "Copy",
                                                    icon=ft.Icons.CONTENT_COPY,
                                                    on_click=self._on_copy_html,
                                                ),
                                                ft.OutlinedButton(
                                                    "Save file",
                                                    icon=ft.Icons.SAVE_ALT,
                                                    on_click=self._on_save_html,
                                                ),
                                                ft.OutlinedButton(
                                                    "Open file",
                                                    icon=ft.Icons.FOLDER_OPEN,
                                                    on_click=self._on_open_file,
                                                ),
                                                ft.OutlinedButton(
                                                    "Reset",
                                                    icon=ft.Icons.RESTART_ALT,
                                                    on_click=self._on_reset_builder,
                                                ),
                                            ],
                                            spacing=6,
                                            wrap=True,
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    wrap=True,
                                ),
                                self.generated_code_view,
                            ],
                            spacing=10,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                    th.section_card(
                        ft.Column(
                            [
                                th.section_title(
                                    "Saved tests", ft.Icons.FOLDER_SPECIAL
                                ),
                                ft.Row(
                                    [
                                        self.session_name_field,
                                        ft.ElevatedButton(
                                            "Save",
                                            icon=ft.Icons.SAVE,
                                            on_click=self._on_save_session,
                                        ),
                                    ],
                                    spacing=10,
                                    wrap=True,
                                ),
                                ft.Row(
                                    [
                                        self.session_dropdown,
                                        ft.OutlinedButton(
                                            "Open",
                                            icon=ft.Icons.FOLDER_OPEN,
                                            on_click=self._on_load_session,
                                        ),
                                        ft.OutlinedButton(
                                            "Delete",
                                            icon=ft.Icons.DELETE_OUTLINE,
                                            on_click=self._on_delete_session,
                                        ),
                                        ft.TextButton(
                                            "Start New Test",
                                            icon=ft.Icons.INSERT_DRIVE_FILE,
                                            on_click=self._on_new_session,
                                        ),
                                    ],
                                    spacing=10,
                                    wrap=True,
                                ),
                            ],
                            spacing=10,
                        ),
                        bgcolor=th.PANEL_DARK_ALT,
                    ),
                ],
                spacing=14,
            ),
        )

    def _on_analyze_click(self, e: ft.Event) -> None:
        self._run_async(self._analyze)

    async def _analyze(self) -> None:
        url = self.url_field.value or ""
        if not url.strip():
            self._toast("Please enter a website address first.", color=th.DANGER)
            return
        port_val = None
        if self.port_field.value:
            try:
                port_val = None
            except ValueError:
                port_val = None
        self.check_progress.visible = True
        self.check_btn.disabled = True
        self.status_strip_text.value = "Checking website..."
        self.page.update()
        result = await self.controller.analyze(url, custom_port=port_val)
        self.check_progress.visible = False
        self.check_btn.disabled = False
        if result.error:
            self.final_url_text.value = "--"
            self.redirect_text.value = "--"
            self.status_code_text.value = "--"
            self.response_time_text.value = "--"
            self.result_icon.name = ft.Icons.ERROR_OUTLINE
            self.result_icon.color = th.DANGER
            self.result_title.value = "Couldn't check this website"
            self.result_title.color = th.DANGER
            self.result_summary.value = result.error
            self.status_strip_text.value = f"Check failed: {result.error}"
            self.page.update()
            return
        self.final_url_text.value = result.final_url or "--"
        self.redirect_text.value = str(result.redirect_count)
        self.status_code_text.value = str(result.status_code)
        self.response_time_text.value = (
            f"{result.response_time_ms} ms" if result.response_time_ms else "--"
        )
        protection = result.protection
        if protection:
            self._set_badge(
                self.xfo_badge,
                f"X-Frame-Options: {protection.x_frame_options.classification.value}",
                (
                    th.TEXT_PRIMARY
                    if protection.x_frame_options.classification.value == "missing"
                    else th.ACCENT
                ),
            )
            self.xfo_detail.value = protection.x_frame_options.explanation
            self._set_badge(
                self.fa_badge,
                f"frame-ancestors: {protection.frame_ancestors.classification.value}",
                th.ACCENT,
            )
            self.fa_detail.value = protection.frame_ancestors.explanation
            v_color = th.verdict_color(protection.verdict.value)
            v_icon = th.verdict_icon(protection.verdict.value)
            self.result_icon.name = v_icon
            self.result_icon.color = v_color
            self.result_title.color = v_color
            headline_map = {
                "protected": "Safe -- protected against clickjacking",
                "partially_protected": "Partially protected",
                "vulnerable": "Not safe -- vulnerable to clickjacking",
                "unknown": "Couldn't determine protection status",
            }
            self.result_title.value = headline_map.get(
                protection.verdict.value, "Result"
            )
            self.result_summary.value = th.simple_verdict_summary(
                protection.verdict.value
            )
        self.status_strip_text.value = "Check complete."
        self.page.update()
        self._regenerate_and_refresh()

    def _on_template_change(self, e: ft.Event) -> None:
        kind = AttackTemplateKind(self.template_dropdown.value)
        state = self.controller.apply_template(kind)
        template = get_template(kind)
        self.template_description.value = template.description
        self.opacity_slider.value = state.iframe_opacity
        self.width_field.value = state.iframe_width
        self.height_field.value = state.iframe_height
        self.overlay_switch.value = state.overlay_enabled
        if template.viewport_width and template.viewport_height:
            self._apply_device_size(template.viewport_width, template.viewport_height)
        self.page.update()
        self._regenerate_and_refresh()

    def _on_builder_change(self, e: ft.Event) -> None:
        state = self.controller.builder_state
        state.iframe_opacity = self.opacity_slider.value
        state.iframe_top = self._safe_int(self.top_field.value, 0)
        state.iframe_left = self._safe_int(self.left_field.value, 0)
        state.iframe_z_index = self._safe_int(self.zindex_field.value, 1)
        state.iframe_width = self.width_field.value or "100%"
        state.iframe_height = self.height_field.value or "100%"
        state.overlay_enabled = bool(self.overlay_switch.value)
        state.overlay_text = self.overlay_text_field.value or state.overlay_text
        state.overlay_top = self._safe_int(self.overlay_top_field.value, 200)
        state.overlay_left = self._safe_int(self.overlay_left_field.value, 150)
        state.overlay_z_index = self._safe_int(self.overlay_zindex_field.value, 2)
        state.overlay_image_url = self.overlay_image_field.value or ""
        state.background_color = self.bgcolor_field.value or "#f2f2f7"
        state.background_image_url = self.bgimage_field.value or ""
        state.custom_html = self.custom_html_field.value or ""
        state.custom_css = self.custom_css_field.value or ""
        state.custom_js = self.custom_js_field.value or ""
        self._regenerate_and_refresh()

    @staticmethod
    def _safe_int(value: Optional[str], default: int) -> int:
        try:
            return int(value) if value else default
        except ValueError:
            return default

    def _on_device_change(self, e: ft.Event) -> None:
        selected = (
            list(self.device_selector.selected)[0]
            if self.device_selector.selected
            else "Desktop"
        )
        self.preview_device = selected
        w, h = VIEWPORT_PRESETS[selected]
        self._apply_device_size(w, h)
        self.page.update()

    def _apply_device_size(self, w: int, h: int) -> None:
        self.preview_frame.width = w * 0.4 * self.preview_zoom
        self.preview_frame.height = h * 0.4 * self.preview_zoom

    def _on_zoom_in(self, e: ft.Event) -> None:
        self.preview_zoom = min(2.0, round(self.preview_zoom + 0.1, 2))
        self._apply_zoom()

    def _on_zoom_out(self, e: ft.Event) -> None:
        self.preview_zoom = max(0.4, round(self.preview_zoom - 0.1, 2))
        self._apply_zoom()

    def _apply_zoom(self) -> None:
        w, h = VIEWPORT_PRESETS[self.preview_device]
        self._apply_device_size(w, h)
        self.zoom_text.value = f"{int(self.preview_zoom * 100)}%"
        self.page.update()

    def _on_refresh_preview(self, e: ft.Event) -> None:
        self._regenerate_and_refresh()
        self._toast("Preview refreshed.")

    def _regenerate_and_refresh(self) -> None:
        html = self.controller.generate_html()
        self.generated_code_view.value = html
        preview_note = ft.Column(
            [
                ft.Icon(ft.Icons.PREVIEW, size=28, color=th.ACCENT),
                ft.Text(
                    'Demo page ready. Click "Create & Open Demo Page" above to see it running for real in your browser.',
                    size=11,
                    color=th.TEXT_MUTED,
                    text_align=ft.TextAlign.CENTER,
                ),
                ft.Text(
                    html_lib.escape(
                        self.controller.builder_state.target_url or "(no website set)"
                    ),
                    size=11,
                    color=th.TEXT_PRIMARY,
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=8,
        )
        self.preview_frame.content = ft.Container(
            content=preview_note, padding=20, alignment=ft.Alignment.CENTER
        )
        if self.controller.server.status.state == ServerState.RUNNING:
            self.controller.refresh_server_content()
        self.page.update()

    def _on_copy_html(self, e: ft.Event) -> None:
        self._run_async(self._copy_html)

    async def _copy_html(self) -> None:
        html = self.controller.generate_html()
        await self.clipboard.set(html)
        self._toast("Code copied to clipboard.", color=th.SUCCESS)

    def _on_save_html(self, e: ft.Event) -> None:
        try:
            path = self.controller.save_poc()
            self._toast(f"Saved: {path}", color=th.SUCCESS)
            self.status_strip_text.value = f"Demo page saved to {path}"
            self.page.update()
        except OSError as exc:
            self._toast(f"Save failed: {exc}", color=th.DANGER)

    def _on_open_file(self, e: ft.Event) -> None:
        if self.controller.last_saved_path is None:
            self._toast("Save the file first.", color=th.WARNING)
            return
        self.controller.open_saved_file()

    def _on_reset_builder(self, e: ft.Event) -> None:
        state = self.controller.reset_builder()
        self.opacity_slider.value = state.iframe_opacity
        self.top_field.value = "0"
        self.left_field.value = "0"
        self.zindex_field.value = "1"
        self.width_field.value = state.iframe_width
        self.height_field.value = state.iframe_height
        self.overlay_switch.value = False
        self.overlay_text_field.value = state.overlay_text
        self.overlay_image_field.value = ""
        self.bgcolor_field.value = state.background_color
        self.bgimage_field.value = ""
        self.custom_html_field.value = ""
        self.custom_css_field.value = ""
        self.custom_js_field.value = ""
        self._regenerate_and_refresh()
        self._toast("Reset to default.")

    def _on_random_port(self, e: ft.Event) -> None:
        port = self.controller.random_port()
        self.port_field.value = str(port)
        self.page.update()

    def _on_start_server(self, e: ft.Event) -> None:
        if not (self.controller.builder_state.target_url or self.url_field.value):
            self._toast("Enter a website address first.", color=th.WARNING)
            return
        if not self.controller.builder_state.target_url:
            self.controller.builder_state.target_url = self.url_field.value
        port = self._safe_int(self.port_field.value, 8765)
        status = self.controller.start_server(port=port)
        self._reflect_server_status(status)

    def _on_stop_server(self, e: ft.Event) -> None:
        status = self.controller.stop_server()
        self._reflect_server_status(status)

    def _on_restart_server(self, e: ft.Event) -> None:
        port = self._safe_int(self.port_field.value, 8765)
        status = self.controller.restart_server(port=port)
        self._reflect_server_status(status)

    def _reflect_server_status(self, status) -> None:
        color = {
            ServerState.RUNNING: th.SUCCESS,
            ServerState.STOPPED: th.TEXT_MUTED,
            ServerState.ERROR: th.DANGER,
            ServerState.STARTING: th.WARNING,
            ServerState.STOPPING: th.WARNING,
        }.get(status.state, th.TEXT_MUTED)
        self._set_badge(
            self.server_status_badge, f"Demo server: {status.state.value}", color
        )
        self.server_url_text.value = status.url or (status.message or "--")
        if status.state == ServerState.RUNNING:
            self._set_badge(self.demo_status_badge, "Demo: running", th.SUCCESS)
            self.demo_url_text.value = f"Open in your browser: {status.url}"
        else:
            self._set_badge(self.demo_status_badge, "Demo: not running", th.TEXT_MUTED)
            self.demo_url_text.value = ""
        self.status_strip_text.value = (
            status.message or f"Demo server {status.state.value}."
        )
        self.page.update()

    def _on_quick_demo(self, e: ft.Event) -> None:
        url = self.controller.builder_state.target_url or self.url_field.value
        if not url or not url.strip():
            self._toast("Enter a website address first.", color=th.WARNING)
            return
        if not self.controller.builder_state.target_url:
            from utils.url_utils import normalize_url

            self.controller.builder_state.target_url = normalize_url(url)
        status = self.controller.start_server_on_random_port()
        self._reflect_server_status(status)
        if status.state != ServerState.RUNNING:
            self._toast(
                status.message or "Could not start the demo server.", color=th.DANGER
            )
            return
        from app.core.models import BrowserKind as _BrowserKind

        launched = self.controller.launch_in_browser(_BrowserKind.DEFAULT)
        if launched:
            self._toast("Demo page opened in your browser.", color=th.SUCCESS)
        else:
            self._toast(
                "Demo server started, but the browser could not be opened automatically. Copy the address below.",
                color=th.WARNING,
            )
        self._regenerate_and_refresh()

    def _on_launch_browsers(self, e: ft.Event) -> None:
        if self.controller.server.status.state != ServerState.RUNNING:
            self._toast("Start the demo server first.", color=th.WARNING)
            return
        browsers = []
        if self.browser_chrome_cb.value:
            browsers.append(BrowserKind.CHROME)
        if self.browser_firefox_cb.value:
            browsers.append(BrowserKind.FIREFOX)
        if self.browser_edge_cb.value:
            browsers.append(BrowserKind.EDGE)
        if self.browser_default_cb.value:
            browsers.append(BrowserKind.DEFAULT)
        if not browsers:
            self._toast("Select at least one browser.", color=th.WARNING)
            return
        launched = self.controller.launch_in_multiple_browsers(browsers)
        self._toast(
            f"Opened in: {', '.join((b.value for b in launched))}"
            if launched
            else "Could not open a browser."
        )

    def _on_validate(self, e: ft.Event) -> None:
        result = self.controller.validate()
        if result is None:
            self._toast("Check a website first.", color=th.WARNING)
            return
        color = {
            ValidationOutcome.LOADED: th.DANGER,
            ValidationOutcome.BLOCKED_X_FRAME_OPTIONS: th.SUCCESS,
            ValidationOutcome.BLOCKED_CSP_FRAME_ANCESTORS: th.SUCCESS,
            ValidationOutcome.BROWSER_RESTRICTION: th.WARNING,
            ValidationOutcome.NETWORK_ERROR: th.WARNING,
            ValidationOutcome.UNKNOWN: th.TEXT_MUTED,
        }.get(result.outcome, th.TEXT_MUTED)
        self._set_badge(
            self.validation_badge,
            f"Result: {result.outcome.value.replace('_', ' ')}",
            color,
        )
        self.validation_detail.value = result.explanation
        self.page.update()

    def _on_new_session(self, e: ft.Event) -> None:
        self.controller.new_session()
        self.url_field.value = ""
        self._on_reset_builder(e)
        self._toast("Started a new test.")

    def _on_save_session(self, e: ft.Event) -> None:
        name = self.session_name_field.value or "Untitled Test"
        path = self.controller.save_session(name)
        self.session_dropdown.options = [
            ft.dropdown.Option(s) for s in self.controller.list_sessions()
        ]
        self.page.update()
        self._toast(f"Saved: {path.name}", color=th.SUCCESS)

    def _on_load_session(self, e: ft.Event) -> None:
        name = self.session_dropdown.value
        if not name:
            self._toast("Choose a saved test to open.", color=th.WARNING)
            return
        session = self.controller.load_session(name)
        self.url_field.value = session.target_url
        self.port_field.value = str(session.port)
        state = session.builder_state
        self.template_dropdown.value = state.template_kind.value
        self.opacity_slider.value = state.iframe_opacity
        self.top_field.value = str(state.iframe_top)
        self.left_field.value = str(state.iframe_left)
        self.zindex_field.value = str(state.iframe_z_index)
        self.width_field.value = state.iframe_width
        self.height_field.value = state.iframe_height
        self.overlay_switch.value = state.overlay_enabled
        self.overlay_text_field.value = state.overlay_text
        self.overlay_top_field.value = str(state.overlay_top)
        self.overlay_left_field.value = str(state.overlay_left)
        self.overlay_zindex_field.value = str(state.overlay_z_index)
        self.overlay_image_field.value = state.overlay_image_url
        self.bgcolor_field.value = state.background_color
        self.bgimage_field.value = state.background_image_url
        self.custom_html_field.value = state.custom_html
        self.custom_css_field.value = state.custom_css
        self.custom_js_field.value = state.custom_js
        self._regenerate_and_refresh()
        self._toast(f"Opened: {name}", color=th.SUCCESS)

    def _on_delete_session(self, e: ft.Event) -> None:
        name = self.session_dropdown.value
        if not name:
            self._toast("Choose a saved test to delete.", color=th.WARNING)
            return
        self.controller.delete_session(name)
        self.session_dropdown.value = None
        self.session_dropdown.options = [
            ft.dropdown.Option(s) for s in self.controller.list_sessions()
        ]
        self.page.update()
        self._toast(f"Deleted: {name}")

    def _on_open_settings(self, e: ft.Event) -> None:
        settings = self.controller.settings
        browser_dd = ft.Dropdown(
            label="Default browser",
            value=settings.default_browser.value,
            options=[ft.dropdown.Option(b.value) for b in BrowserKind],
            bgcolor=th.PANEL_DARK_ALT,
            color=th.TEXT_PRIMARY,
        )
        port_field = ft.TextField(
            label="Default port",
            value=str(settings.default_port),
            keyboard_type=ft.KeyboardType.NUMBER,
            bgcolor=th.PANEL_DARK_ALT,
            color=th.TEXT_PRIMARY,
        )
        template_dd = ft.Dropdown(
            label="Default attack style",
            value=settings.default_attack_template.value,
            options=[
                ft.dropdown.Option(t.kind.value, t.name)
                for t in self.controller.templates()
            ],
            bgcolor=th.PANEL_DARK_ALT,
            color=th.TEXT_PRIMARY,
        )
        theme_dd = ft.Dropdown(
            label="Theme",
            value=settings.theme,
            options=[ft.dropdown.Option("dark"), ft.dropdown.Option("light")],
            bgcolor=th.PANEL_DARK_ALT,
            color=th.TEXT_PRIMARY,
        )
        dialog = ft.AlertDialog(modal=True, title=ft.Text("Settings"))

        def save_and_close(ev: ft.Event) -> None:
            settings.default_browser = BrowserKind(browser_dd.value)
            settings.default_port = self._safe_int(port_field.value, 8765)
            settings.default_attack_template = AttackTemplateKind(template_dd.value)
            settings.theme = theme_dd.value
            self.controller.save_settings()
            self._close_dialog(dialog)
            self._toast("Settings saved.", color=th.SUCCESS)

        def reset_and_close(ev: ft.Event) -> None:
            self.controller.reset_settings()
            self._close_dialog(dialog)
            self._toast("Settings reset to defaults.")

        def cancel(ev: ft.Event) -> None:
            self._close_dialog(dialog)

        dialog.content = ft.Column(
            [browser_dd, port_field, template_dd, theme_dd],
            spacing=12,
            width=340,
            height=260,
        )
        dialog.actions = [
            ft.TextButton("Reset everything", on_click=reset_and_close),
            ft.TextButton("Cancel", on_click=cancel),
            ft.FilledButton("Save", on_click=save_and_close),
        ]
        self._show_dialog(dialog)


def main(page: ft.Page) -> None:
    ClickjackingTesterApp(page)
