"""
EchoRisk AI — Root Application Entrypoint
Delegates execution to the backend server in `backend/app.py`.
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV", "development").lower() == "development"
    print(f"[*] Starting EchoRisk AI server on http://localhost:{port} (debug={debug_mode})")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
