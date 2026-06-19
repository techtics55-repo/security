@echo off
REM Build Aegis Agent for Windows
REM Requires: Python 3.10+, PyInstaller

cd /d "%~dp0.."

echo Installing build dependencies...
pip install pyinstaller
pip install -r requirements.txt
pip install pystray pywebview pillow

echo Building Aegis Agent executable...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "AegisAgent" ^
    --icon agent_app\icon.ico ^
    --add-data "static;static" ^
    --add-data "agent;agent" ^
    --add-data "backend;backend" ^
    --hidden-import backend.main ^
    --hidden-import backend.routes.auth ^
    --hidden-import backend.routes.logs ^
    --hidden-import backend.routes.agents ^
    --hidden-import backend.routes.billing ^
    --hidden-import backend.routes.scanner_features ^
    --hidden-import backend.database ^
    --hidden-import backend.models ^
    --hidden-import backend.middleware.auth ^
    --hidden-import backend.config ^
    --hidden-import agent.scanners ^
    --hidden-import uvicorn ^
    --hidden-import pystray ^
    --hidden-import PIL ^
    agent_app\launcher.py

echo Copying build output...
copy "dist\AegisAgent.exe" "downloads\aegis-agent-x86_64.exe"

echo Done! Output: downloads\aegis-agent-x86_64.exe
