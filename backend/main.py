import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager

from .config import settings
from .database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = Path(__file__).parent.parent / "static"
has_static = static_dir.exists()

if has_static:
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


    @app.get("/")
    def serve_index():
        return FileResponse(str(static_dir / "index.html"))


    @app.get("/app")
    def serve_app():
        app_file = static_dir / "app.html"
        if app_file.exists():
            return FileResponse(str(app_file))
        return FileResponse(str(static_dir / "index.html"))


    @app.get("/billing")
    def serve_billing():
        app_file = static_dir / "app.html"
        if app_file.exists():
            return FileResponse(str(app_file))
        return FileResponse(str(static_dir / "index.html"))
else:

    @app.get("/")
    def root():
        return {
            "name": settings.app_name,
            "version": settings.version,
            "status": "running",
        }


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": __import__("datetime").datetime.utcnow().isoformat()}


from .routes.auth import router as auth_router
from .routes.logs import router as logs_router
from .routes.agents import router as agents_router
from .routes.billing import router as billing_router
from .routes.scanner_features import router as scanner_features_router
from .routes.downloads import router as downloads_router

app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(agents_router)
app.include_router(billing_router)
app.include_router(scanner_features_router)
app.include_router(downloads_router)
