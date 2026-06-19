#!/bin/bash
# Build Aegis Agent for Linux (.deb package)
# Requires: Python 3.10+, PyInstaller, fpm (or dpkg-deb)

set -e
cd "$(dirname "$0")/.."

echo "Installing build dependencies..."
pip install pyinstaller
pip install -r requirements.txt
pip install pystray pywebview pillow

echo "Building Aegis Agent executable..."
pyinstaller \
    --onefile \
    --name "aegis-agent" \
    --add-data "static:static" \
    --add-data "agent:agent" \
    --add-data "backend:backend" \
    --hidden-import backend.main \
    --hidden-import backend.routes.auth \
    --hidden-import backend.routes.logs \
    --hidden-import backend.routes.agents \
    --hidden-import backend.routes.billing \
    --hidden-import backend.routes.scanner_features \
    --hidden-import backend.database \
    --hidden-import backend.models \
    --hidden-import backend.middleware.auth \
    --hidden-import backend.config \
    --hidden-import agent.scanners \
    --hidden-import uvicorn \
    --hidden-import pystray \
    --hidden-import PIL \
    agent_app/launcher.py

cp "dist/aegis-agent" "downloads/aegis-agent_amd64.deb"
chmod +x "downloads/aegis-agent_amd64.deb"

echo "Done! Output: downloads/aegis-agent_amd64.deb"
