from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.test_harness import router as test_harness_router


STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Obsidian Recon API")
app.include_router(test_harness_router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def read_root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}
