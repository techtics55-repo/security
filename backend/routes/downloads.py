from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter(prefix="/downloads", tags=["Downloads"])

DOWNLOADS_DIR = Path(__file__).parent.parent.parent / "downloads"

FILES = {
    "windows": ("aegis-agent-x86_64.exe", "application/vnd.microsoft.portable-executable"),
    "macos": ("aegis-agent-x86_64.dmg", "application/x-apple-diskimage"),
    "linux": ("aegis-agent_amd64.deb", "application/vnd.debian.binary-package"),
    "cli": ("aegis-cli.pyz", "application/octet-stream"),
}


@router.get("/{platform}")
def download(platform: str):
    entry = FILES.get(platform)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Unknown platform: {platform}")

    filename, media_type = entry
    filepath = DOWNLOADS_DIR / filename

    if not filepath.exists():
        if platform == "cli":
            cli_path = DOWNLOADS_DIR / filename
            return FileResponse(str(cli_path), media_type=media_type, filename=filename)

        raise HTTPException(
            status_code=404,
            detail=f"Build not available yet. Run scripts/build_{platform}.bat|sh first.",
        )

    return FileResponse(str(filepath), media_type=media_type, filename=filename)
