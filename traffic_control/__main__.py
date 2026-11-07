"""Start AI Traffic Control desktop UI and local gateway services."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .service import AppServices
from .ui import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("AI Traffic Control")
    services = AppServices()
    # The services and credential settings are ready before the listener binds.
    # Startup binds only to loopback and makes no upstream request.
    services.gateway.start(services.settings)
    window = MainWindow(service=services, gateway=services.gateway, settings=services.settings)
    app.aboutToQuit.connect(services.close)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
