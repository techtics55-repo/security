import sys
import os
import threading

from .service import AegisService
from .tray import run_tray


def main():
    service = AegisService()
    service.start()

    tray_thread = threading.Thread(target=run_tray, args=(service,), daemon=True)
    tray_thread.start()

    try:
        tray_thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()


if __name__ == "__main__":
    main()
