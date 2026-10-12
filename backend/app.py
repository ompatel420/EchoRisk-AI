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
TEMPLATE_DIR = os.path.join(FRONTEND_DIR, "templates")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

# Load environment configuration
env_path = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(env_path):
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

import time
from collections import defaultdict
from threading import Lock

try:
    from backend.utils.validators import validate_and_normalize_email, mask_email
    from backend.services.breach_service import check_email_breaches, get_breach_detail
    from backend.services.ai_service import analyze_risk_with_claude
    from backend.services.report_service import assemble_final_report
except ImportError:
    from utils.validators import validate_and_normalize_email, mask_email
    from services.breach_service import check_email_breaches, get_breach_detail
    from services.ai_service import analyze_risk_with_claude
    from services.report_service import assemble_final_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("echorisk-backend")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "echorisk-dev-secret-key-default")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request payload limit

# In-memory sliding-window rate limiter for public API endpoints
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30  # requests per window per IP
_ip_request_timestamps = defaultdict(list)
_rate_limit_lock = Lock()


def get_client_ip() -> str:
    """Extracts client IP address safely, checking reverse-proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def is_rate_limited(ip: str) -> bool:
    """Thread-safe sliding window rate check with memory-leak cleanup."""
    now = time.time()
    with _rate_limit_lock:
        timestamps = [ts for ts in _ip_request_timestamps.get(ip, []) if now - ts < RATE_LIMIT_WINDOW]
        if not timestamps:
            _ip_request_timestamps.pop(ip, None)
        else:
            _ip_request_timestamps[ip] = timestamps
        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            return True
        _ip_request_timestamps.setdefault(ip, []).append(now)
        return False


@app.after_request
def set_security_headers(response):
    """Applies hardened HTTP response security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    csp_directives = [
        "default-src 'self'",
        "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'unsafe-inline'",
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
        "font-src 'self' https://fonts.gstatic.com data:",
        "img-src 'self' data: https://xposedornot.com https:",
        "connect-src 'self' https://passwords.xposedornot.com https://api.xposedornot.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self' javascript:"
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
    return response


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handles oversized request bodies gracefully."""
    return jsonify({
        "status": "error",
        "code": "PAYLOAD_TOO_LARGE",
        "message": "Request payload exceeds maximum allowed size (1 MB)."
    }), 413


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
    """Core breach lookup and risk evaluation endpoint with rate limiting."""
    client_ip = get_client_ip()
    if is_rate_limited(client_ip):
        logger.warning("Rate limit exceeded for IP: %s on /api/scan", client_ip)
        resp = jsonify({
            "status": "error",
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "Too many requests. Please wait a minute before scanning again."
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
        return resp

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
