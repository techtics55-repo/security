import sys
import logging
import webbrowser
import os

import pystray
from PIL import Image, ImageDraw

from .service import AegisService, logger

ICON_SIZE = 64


def _create_icon_image(color="#44e2cd"):
    img = Image.new("RGBA", (ICON_SIZE, ICON_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = ICON_SIZE // 2, ICON_SIZE // 2
    r = ICON_SIZE // 2 - 4
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=None, outline=color, width=3)
    r2 = r // 2
    draw.ellipse([cx - r2, cy - r2, cx + r2, cy + r2], fill=color)
    draw.polygon([(cx - 6, cy + 2), (cx + 6, cy + 2), (cx, cy + 10)], fill=(5, 20, 36))
    return img


class AegisTray:
    def __init__(self, service: AegisService, on_show_window=None, on_quit=None):
        self._service = service
        self._icon = None
        self._on_show_window = on_show_window
        self._on_quit = on_quit
        self._window_visible = False

    def _build_menu(self):
        status = self._service.status()
        enabled = status["enabled"]
        running = status["running"]

        status_text = "● Protected" if enabled else "○ Paused"
        if not running:
            status_text = "○ Stopped"

        items = [
            pystray.MenuItem(status_text, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Show Window" if not self._window_visible else "Hide Window",
                self._toggle_window,
            ),
            pystray.MenuItem(
                "Pause Security" if enabled else "Resume Security",
                self._toggle_enabled,
            ),
            pystray.MenuItem("Open Dashboard in Browser", self._open_dashboard),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Aegis", self._quit),
        ]
        return items

    def _toggle_window(self):
        if self._on_show_window:
            self._on_show_window()

    def toggle_window(self):
        self._window_visible = not self._window_visible
        if self._icon:
            self._icon.menu = pystray.Menu(*self._build_menu())
            self._icon.update_menu()

    def _toggle_enabled(self):
        status = self._service.status()
        if status["enabled"]:
            self._service.disable()
        else:
            self._service.enable()
        self._update_icon()

    def _open_dashboard(self):
        port = self._service.status()["port"]
        url = f"http://127.0.0.1:{port}/app"
        logger.info(f"Opening dashboard: {url}")
        webbrowser.open(url)

    def _quit(self):
        logger.info("Quitting Aegis Agent")
        self._service.stop()
        if self._icon:
            self._icon.stop()
        if self._on_quit:
            self._on_quit()
        os._exit(0)

    def _update_icon(self):
        if self._icon:
            status = self._service.status()
            color = "#44e2cd" if status["enabled"] else "#7a9ab0"
            self._icon.icon = _create_icon_image(color)
            self._icon.menu = pystray.Menu(*self._build_menu())
            self._icon.update_menu()

    def run(self):
        icon_img = _create_icon_image("#44e2cd")
        self._icon = pystray.Icon(
            "aegis-agent",
            icon_img,
            "Aegis Agent",
            pystray.Menu(*self._build_menu()),
        )
        self._icon.run()


def run_tray(service: AegisService, on_show_window=None, on_quit=None):
    tray = AegisTray(service, on_show_window=on_show_window, on_quit=on_quit)
    tray.run()
