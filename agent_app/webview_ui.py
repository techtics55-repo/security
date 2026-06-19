import sys
import threading
import logging
import os

logger = logging.getLogger("aegis")

_webview_window = None
_webview_ready = threading.Event()


def open_dashboard(port):
    try:
        import webview

        global _webview_window

        url = f"http://127.0.0.1:{port}/app"

        def on_loaded():
            _webview_ready.set()
            logger.info("Webview window loaded")

        _webview_window = webview.create_window(
            title="Aegis Agent",
            url=url,
            width=1280,
            height=800,
            min_size=(900, 600),
            resizable=True,
            fullscreen=False,
            text_select=True,
            confirm_close=True,
            js_api=None,
        )

        logger.info(f"Opening webview window at {url}")
        webview.start(
            gui=None,
            debug=False,
            http_server=False,
            private_mode=False,
        )
    except ImportError:
        logger.info("pywebview not available, falling back to browser")
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{port}/app")
        _webview_ready.set()
    except Exception as e:
        logger.warning(f"Failed to start webview: {e}")
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{port}/app")
        _webview_ready.set()


def show_window():
    global _webview_window
    if _webview_window:
        try:
            _webview_window.show()
        except Exception:
            pass


def hide_window():
    global _webview_window
    if _webview_window:
        try:
            _webview_window.hide()
        except Exception:
            pass
