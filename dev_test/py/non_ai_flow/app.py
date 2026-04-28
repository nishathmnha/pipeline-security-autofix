from __future__ import annotations

    
try:
    from .env_loader import load_project_env
    from . import github_service
except ImportError:  
    from env_loader import load_project_env
    import github_service

from fastapi import FastAPI


app = FastAPI(title="Jenkins Failure Log Monitor", version="0.3.0")
app.include_router(github_service.router)

try:
    from . import dashboard_ui  # noqa: F401
    from . import jenkins_service  # noqa: F401
except ImportError:
    import dashboard_ui  # noqa: F401
    import jenkins_service  # noqa: F401
