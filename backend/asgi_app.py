"""
FastAPI / ASGI Application Wrapper
Enables enterprise ASGI deployment (Uvicorn / Docker / Cloud Run)
for the Zero-Knowledge Secure File Vault.
"""

from contextlib import asynccontextmanager
from typing import Optional
from pydantic import BaseModel, Field

from backend.storage import storage
from backend.cleaner import cleaner

try:
    from fastapi import FastAPI, HTTPException, status
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


class UploadRequest(BaseModel):
    ciphertext: str = Field(..., description="Base64 encoded AES-GCM ciphertext")
    iv: str = Field(..., description="Base64 encoded 96-bit IV")
    salt: Optional[str] = Field(default="", description="Base64 encoded 128-bit PBKDF2 salt")
    encrypted_filename: Optional[str] = Field(default="", description="Encrypted original filename")
    expires_in: int = Field(default=86400, ge=60, le=604800, description="Expiration in seconds")
    max_downloads: int = Field(default=1, ge=0, description="1 for burn after reading, 0 for unlimited")


if FASTAPI_AVAILABLE:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        cleaner.start()
        yield
        cleaner.stop()

    app = FastAPI(
        title="Zero-Knowledge Secure File Vault API",
        description="End-to-End Encrypted ephemeral file storage with AES-256-GCM and zero server trust.",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/vault/stats")
    def get_stats():
        return storage.get_stats()

    @app.post("/api/vault/upload", status_code=status.HTTP_201_CREATED)
    def upload_encrypted_blob(req: UploadRequest):
        try:
            return storage.store_blob(
                ciphertext_b64=req.ciphertext,
                iv_b64=req.iv,
                salt_b64=req.salt or "",
                encrypted_filename_b64=req.encrypted_filename or "",
                expires_in_seconds=req.expires_in,
                max_downloads=req.max_downloads,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/vault/meta/{file_id}")
    def get_metadata(file_id: str):
        st, meta = storage.get_metadata(file_id)
        if st == "OK":
            return {"success": True, "metadata": meta}
        elif st == "EXPIRED":
            raise HTTPException(status_code=410, detail="File expired and shredded.")
        raise HTTPException(status_code=404, detail="File not found or already burned.")

    @app.get("/api/vault/file/{file_id}")
    def retrieve_file(file_id: str):
        st, payload = storage.retrieve_blob(file_id)
        if st == "OK":
            return {"success": True, "payload": payload}
        elif st == "EXPIRED":
            raise HTTPException(status_code=410, detail="File expired and shredded.")
        raise HTTPException(status_code=404, detail="File not found or already burned.")

else:
    app = None
