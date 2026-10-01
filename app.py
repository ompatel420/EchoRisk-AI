"""
EchoRisk AI — Root Application Entrypoint
Delegates execution to the modular backend server in `backend/app.py`.
"""
import os
import sys

# Ensure backend directory is in Python module search path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    from backend.app import app
except ImportError:
    from app import app

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV", "development").lower() == "development"
    print(f"[*] Starting EchoRisk AI server on http://localhost:{port} (debug={debug_mode})")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
