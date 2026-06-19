import sys
import os
import threading
import logging

logger = logging.getLogger("aegis")


def main():
    try:
        import agent_app
    except Exception:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from .service import AegisService, logger
    from .tray import run_tray
    from . import webview_ui

    service = AegisService()

    logger.info("Starting Aegis Agent...")
    port = service.start()
    if port is None:
        logger.error("Failed to start backend. Exiting.")
        sys.exit(1)

    logger.info(f"Dashboard available at http://127.0.0.1:{port}/app")

    tray_on_show = lambda: webview_ui.show_window()
    tray_on_quit = lambda: service.stop()

    tray_thread = threading.Thread(
        target=run_tray,
        args=(service,),
        kwargs={"on_show_window": tray_on_show, "on_quit": tray_on_quit},
        daemon=True,
    )
    tray_thread.start()

    webview_ui.open_dashboard(port)

    logger.info("Aegis Agent shutting down...")
    service.stop()


if __name__ == "__main__":
    main()
