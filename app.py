"""Compatibility entrypoint for local development.

Use ``uvicorn app.main:app`` in production. This file keeps the familiar
``python app.py`` command working for Kali users.
"""

import uvicorn

from app.config import settings


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)
