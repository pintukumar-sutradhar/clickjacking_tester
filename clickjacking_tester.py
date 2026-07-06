from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import flet as ft
from app.ui.main_view import main as build_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clickjacking Tester")
    parser.add_argument(
        "--web",
        action="store_true",
        help="Run the UI as a local web application instead of a native desktop window.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port for the Flet UI itself when running with --web (0 = auto-select).",
    )
    return parser.parse_args()


def run() -> None:
    args = parse_args()
    view = ft.AppView.WEB_BROWSER if args.web else ft.AppView.FLET_APP
    ft.run(build_app, view=view, port=args.port)


if __name__ == "__main__":
    run()
