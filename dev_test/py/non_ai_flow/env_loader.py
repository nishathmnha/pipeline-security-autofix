from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_project_env() -> None:
    current_file = Path(__file__).resolve()
    candidate_paths = [
        current_file.parents[3] / ".env",
        current_file.parents[1] / ".env",
        current_file.parent / ".env",
    ]

    for env_path in candidate_paths:
        if env_path.exists():
            load_dotenv(env_path, override=False)
