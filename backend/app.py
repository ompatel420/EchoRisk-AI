"""
EchoRisk AI — Email Data Breach Tracker
Backend Flask Application Entrypoint.
"""
import os
import sys
import logging
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
TEMPLATE_DIR = os.path.join(FRONTEND_DIR, "templates") if os.path.isdir(os.path.join(FRONTEND_DIR, "templates")) else os.path.join(BACKEND_DIR, "templates")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static") if os.path.isdir(os.path.join(FRONTEND_DIR, "static")) else os.path.join(BACKEND_DIR, "static")

# Load environment configuration
for env_path in [os.path.join(PROJECT_ROOT, ".env"), os.path.join(BACKEND_DIR, ".env")]:
    if os.path.exists(env_path):
        load_dotenv(dotenv_path=env_path)
        break
else:
    load_dotenv()

from utils.validators import validate_and_normalize_email, mask_email
from services.breach_service import check_email_breaches, get_breach_detail
from services.ai_service import analyze_risk_with_claude
from services.report_service import assemble_final_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("echorisk-backend")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "echorisk-dev-secret-key-default")


@app.route("/")
def home():
    """Serves the EchoRisk AI frontend landing page."""
    return render_template("index.html")


@app.route("/breach/<path:breach_id>")
def breach_detail_page(breach_id):
    """Serves the dedicated incident dossier for a specific data breach."""
    return render_template("breach_detail.html", breach=get_breach_detail(breach_id))


@app.route("/api/breach/<path:breach_id>", methods=["GET"])
def api_breach_detail(breach_id):
    """JSON API endpoint returning normalized incident data for a specific breach."""
    return jsonify(get_breach_detail(breach_id)), 200


@app.route("/health", methods=["GET"])
def health():
    """System health check and provider readiness probe."""
    return jsonify({
        "status": "ok",
        "app": "EchoRisk AI — Email Data Breach Tracker",
        "version": "1.0.0",
        "ai_service_configured": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
        "mock_mode": os.environ.get("MOCK_MODE", "false").lower() in ("true", "1", "yes"),
        "privacy_rule": "Zero permanent storage of scanned emails"
    }), 200


@app.route("/api/scan", methods=["POST"])
def scan_email():
    """Core breach lookup and risk evaluation endpoint."""
    if not request.is_json:
        return jsonify({"status": "error", "code": "INVALID_CONTENT_TYPE", "message": "Request must be JSON."}), 400

    raw_email = (request.get_json() or {}).get("email")
    is_valid, normalized_email, err_msg, suggestion = validate_and_normalize_email(raw_email)
    if not is_valid or not normalized_email:
        err = {"status": "error", "code": "INVALID_EMAIL", "message": err_msg or "Please provide a valid email."}
        if suggestion:
            err["suggestion"] = suggestion
        return jsonify(err), 400

    masked = mask_email(normalized_email)
    logger.info("Initiating breach scan for masked target: %s", masked)

    try:
        breach_facts = check_email_breaches(normalized_email)
        if breach_facts.get("status") == "error" and breach_facts.get("breach_count", 0) == 0:
            return jsonify({
                "status": "error",
                "code": "PROVIDER_UNAVAILABLE",
                "message": breach_facts.get("message", "Breach database service is temporarily unreachable.")
            }), 503

        ai_assessment = analyze_risk_with_claude(breach_facts)
        report = assemble_final_report(masked_email=masked, breach_facts=breach_facts, ai_assessment=ai_assessment)
        logger.info("Scan completed for: %s (breaches: %d)", masked, breach_facts.get("breach_count", 0))
        return jsonify(report), 200

    except Exception as e:
        logger.error("Internal processing error: %s", str(e))
        return jsonify({
            "status": "error",
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An error occurred while evaluating breach records. Please try again later."
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development").lower() == "development"
    print(f"[*] Starting EchoRisk AI server on http://localhost:{port} (debug={debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
