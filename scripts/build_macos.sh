#!/bin/bash
# Build Aegis Agent for macOS
# Requires: Python 3.10+, py2app

set -e
cd "$(dirname "$0")/.."

echo "Installing build dependencies..."
pip install py2app
pip install -r requirements.txt
pip install pystray pywebview pillow

echo "Building Aegis Agent .app bundle..."
cat > setup.py << 'PYEOF'
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from setuptools import setup

APP = ['agent_app/launcher.py']
DATA_FILES = [
    ('static', ['static/index.html', 'static/app.html']),
]
OPTIONS = {
    'argv_emulation': True,
    'packages': [
        'backend', 'agent', 'uvicorn', 'pystray', 'PIL', 'webview',
    ],
    'includes': [
        'backend.main', 'backend.routes.auth', 'backend.routes.logs',
        'backend.routes.agents', 'backend.routes.billing',
        'backend.routes.scanner_features', 'backend.database',
        'backend.models', 'backend.middleware.auth', 'backend.config',
    ],
    'plist': {
        'CFBundleName': 'Aegis Agent',
        'CFBundleDisplayName': 'Aegis Agent',
        'CFBundleIdentifier': 'com.aegis.security.agent',
        'CFBundleVersion': '1.0.0',
        'LSUIElement': True,
    },
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
PYEOF

python setup.py py2app

echo "Creating .dmg..."
mkdir -p dist_dmg
cp -r "dist/Aegis Agent.app" dist_dmg/
hdiutil create -volname "Aegis Agent" -srcfolder dist_dmg -ov -format UDZO "downloads/aegis-agent-x86_64.dmg"

echo "Done! Output: downloads/aegis-agent-x86_64.dmg"
