from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import sys

router = APIRouter(prefix="/downloads", tags=["Downloads"])


def get_downloads_dir():
    candidates = []
    
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).parent
        candidates.append(exe_dir / "downloads")
        candidates.append(exe_dir.parent / "downloads")
        candidates.append(exe_dir.parent.parent / "downloads")
        if hasattr(sys, "_MEIPASS"):
            candidates.append(Path(sys._MEIPASS) / "downloads")
    else:
        base = Path(__file__).parent.parent.parent
        candidates.append(base / "downloads")
    
    for c in candidates:
        if c.exists():
            return c
    
    return candidates[0] if candidates else Path.cwd() / "downloads"


FILES = {
    "windows": ("aegis-agent-x86_64.exe", "application/octet-stream"),
    "macos": ("aegis-agent-x86_64.dmg", "application/octet-stream"),
    "linux": ("aegis-agent_amd64.deb", "application/octet-stream"),
    "cli": ("aegis-cli.pyz", "application/octet-stream"),
}


@router.get("/{platform}")
def download(platform: str):
    entry = FILES.get(platform)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Unknown platform: {platform}")

    filename, media_type = entry
    filepath = get_downloads_dir() / filename

    if not filepath.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Build not available for {platform}. Run the appropriate build script first.",
        )

    return FileResponse(
        str(filepath),
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
