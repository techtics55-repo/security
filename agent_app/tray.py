import sys
import threading
import webbrowser
from pathlib import Path

import pystray
from PIL import Image

from .service import AegisService

ICON_SIZE = 64


def _create_icon_image(color="#44e2cd"):
    img = Image.new("RGBA", (ICON_SIZE, ICON_SIZE), (0, 0, 0, 0))
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    cx, cy = ICON_SIZE // 2, ICON_SIZE // 2
    r = ICON_SIZE // 2 - 4
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=None, outline=color, width=3)
    r2 = r // 2
    draw.ellipse([cx - r2, cy - r2, cx + r2, cy + r2], fill=color)
    draw.polygon([(cx - 6, cy + 2), (cx + 6, cy + 2), (cx, cy + 10)], fill=(5, 20, 36))
    return img


class AegisTray:
    def __init__(self, service: AegisService):
        self._service = service
        self._icon = None
        self._menu_items = {}

    def _build_menu(self):
        status = self._service.status()
        enabled = status["enabled"]
        running = status["running"]

        status_text = f"{'●' if enabled else '○'} {'Protected' if enabled else 'Paused'}"
        if not running:
            status_text = "○ Stopped"

        self._menu_items = {
            "status": pystray.MenuItem(status_text, None, enabled=False),
            "sep1": pystray.Menu.SEPARATOR,
            "toggle": pystray.MenuItem(
                "Pause Security" if enabled else "Resume Security",
                self._toggle_enabled,
                default=True,
            ),
            "dashboard": pystray.MenuItem("Open Dashboard", self._open_dashboard),
            "sep2": pystray.Menu.SEPARATOR,
            "quit": pystray.MenuItem("Quit Aegis", self._quit),
        }
        return list(self._menu_items.values())

    def _toggle_enabled(self):
        status = self._service.status()
        if status["enabled"]:
            self._service.disable()
        else:
            self._service.enable()
        self._update_icon()

    def _open_dashboard(self):
        port = self._service.status()["port"]
        webbrowser.open(f"http://127.0.0.1:{port}/app")

    def _quit(self):
        self._service.stop()
        if self._icon:
            self._icon.stop()
        import os
        os._exit(0)

    def _update_icon(self):
        if self._icon:
            status = self._service.status()
            color = "#44e2cd" if status["enabled"] else "#7a9ab0"
            icon_img = _create_icon_image(color)
            self._icon.icon = icon_img
            self._icon.menu = pystray.Menu(*self._build_menu())
            self._icon.update_menu()

    def run(self):
        icon_img = _create_icon_image("#44e2cd")
        self._icon = pystray.Icon("aegis-agent", icon_img, "Aegis Agent", self._build_menu())
        self._icon.run()


def run_tray(service: AegisService):
    tray = AegisTray(service)
    tray.run()
