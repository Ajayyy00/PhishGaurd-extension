"""Compatibility package: both Python entry points use the complete secured API.
Legacy heuristic helpers remain in app/routes.py for reference/import compatibility.
"""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("phishguard_application", Path(__file__).parents[1] / "app.py")
_application = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_application)
create_app = _application.create_app
