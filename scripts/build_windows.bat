@echo off
REM ============================================
REM Build Aegis Agent for Windows (Full Pipeline)
REM ============================================
cd /d "%~dp0.."

echo === Step 1: Build agent executable with PyInstaller ===
python -m PyInstaller aegis_agent.spec --clean --noconfirm
if %errorlevel% neq 0 (
    echo PyInstaller build failed!
    exit /b %errorlevel%
)

echo === Step 2: Copy to downloads ===
copy /Y "dist\AegisAgent.exe" "downloads\aegis-agent-x86_64.exe"

echo === Step 3: Build installer (requires Inno Setup) ===
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" scripts\installer_windows.iss
    echo Installer created in downloads\
) else (
    echo Inno Setup not found. Skipping installer build.
    echo Download Inno Setup from https://jrsoftware.org/isdl.php
)

echo === Done! ===
echo Files:
echo   downloads\aegis-agent-x86_64.exe  (portable executable)
echo   downloads\AegisAgent-Setup-*.exe   (installer, if Inno Setup available)
