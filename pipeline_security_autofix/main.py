from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "pipeline_security_autofix.api.app:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").strip().lower() in {"1", "true", "yes", "on"},
    )


if __name__ == "__main__":
    main()
