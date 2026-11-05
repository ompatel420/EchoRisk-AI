"""
EchoRisk AI — Core System & Pipeline Test Suite
Automated regression tests covering input validation, risk scoring, report assembly,
API endpoints, rate limiting, and incident dossier generation.
"""
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Prevent writing .pyc files
sys.dont_write_bytecode = True

from backend.input_validator import validate_and_normalize_email, mask_email, levenshtein_distance
from backend.ai_risk_engine import _generate_fallback_assessment
from backend.report_builder import assemble_final_report
from backend.app import app, _ip_request_timestamps, _rate_limit_lock


class TestInputValidator(unittest.TestCase):
    """Verifies email validation, typo detection, and privacy masking."""

    def test_valid_emails(self):
        valid_cases = [
            "alex@example.com",
            "john.doe@test.com",
            "developer+security@example.org",
            "contact_us@example.net"
        ]
        for email in valid_cases:
            is_valid, normalized, err, suggestion = validate_and_normalize_email(email)
            self.assertTrue(is_valid, f"Expected {email} to be valid")
            self.assertEqual(normalized, email.lower())
            self.assertIsNone(err)

    def test_invalid_email_formats(self):
        invalid_cases = [
            ("", "Please provide an email address."),
            ("plainaddress", "Please enter a valid email address with a single '@'."),
            ("two@@at.com", "Please enter a valid email address with a single '@'."),
            (".startsdot@example.com", "Email username is invalid"),
            ("user@.startsdot.com", "Email domain appears invalid"),
            ("user@invalidtld.c", "Invalid domain extension"),
        ]
        for email, expected_err_sub in invalid_cases:
            is_valid, normalized, err, _ = validate_and_normalize_email(email)
            self.assertFalse(is_valid, f"Expected {email} to be invalid")
            self.assertIn(expected_err_sub, err)

    def test_typo_alias_suggestions(self):
        typo_cases = [
            ("user@gmial.com", "user@gmail.com"),
            ("user@hotmial.com", "user@hotmail.com"),
            ("user@outlok.com", "user@outlook.com"),
            ("user@protonmial.com", "user@proton.me")
        ]
        for typo, expected_fix in typo_cases:
            is_valid, _, _, suggestion = validate_and_normalize_email(typo)
            self.assertFalse(is_valid)
            self.assertEqual(suggestion, expected_fix)

    def test_mask_email(self):
        self.assertEqual(mask_email("alexander@example.com"), "a***r@example.com")
        self.assertEqual(mask_email("om@example.com"), "o*@example.com")
        self.assertEqual(mask_email("o@example.com"), "o*@example.com")
        self.assertEqual(mask_email(""), "hidden@anonymous")
        self.assertEqual(mask_email("no_at_sign"), "hidden@anonymous")
        self.assertEqual(mask_email("@domain.com"), "*@domain.com")

    def test_levenshtein_distance(self):
        self.assertEqual(levenshtein_distance("gmail.com", "gmial.com"), 2)
        self.assertEqual(levenshtein_distance("same", "same"), 0)
        self.assertEqual(levenshtein_distance("abc", "def"), 3)


class TestAIRiskEngine(unittest.TestCase):
    """Verifies deterministic security rules and risk scoring bounds."""

    def test_zero_breaches_assessment(self):
        facts = {
            "breach_count": 0,
            "has_password_exposure": False,
            "exposed_data_types": []
        }
        res = _generate_fallback_assessment(facts)
        self.assertEqual(res["risk_level"], "Low")
        self.assertEqual(res["risk_score"], 10)
        self.assertFalse(res["ai_powered"])
        self.assertTrue(res["fallback_used"])
        self.assertTrue(len(res["recommended_actions"]) >= 3)

    def test_breaches_with_password_exposure(self):
        facts = {
            "breach_count": 3,
            "has_password_exposure": True,
            "exposed_data_types": ["Email Addresses", "Passwords", "Usernames"]
        }
        res = _generate_fallback_assessment(facts)
        self.assertIn(res["risk_level"], ("High", "Critical"))
        self.assertTrue(res["risk_score"] >= 75)
        self.assertTrue(any("password" in a.lower() for a in res["recommended_actions"]))

    def test_score_boundaries(self):
        facts = {"breach_count": 50, "has_password_exposure": True, "exposed_data_types": ["Passwords"]}
        res = _generate_fallback_assessment(facts)
        self.assertTrue(10 <= res["risk_score"] <= 100)


class TestReportBuilder(unittest.TestCase):
    """Verifies standardization of final JSON reports."""

    def test_assemble_final_report(self):
        facts = {
            "breach_count": 1,
            "has_password_exposure": False,
            "exposed_data_types": ["Email Addresses"],
            "breaches": [{"breach_title": "TestBreach", "breach_date": "2024-01-01"}]
        }
        ai = {
            "risk_level": "Moderate",
            "risk_score": 45,
            "short_summary": "Test summary",
            "key_findings": ["One exposure found"],
            "recommended_actions": ["Change passwords"],
            "ai_powered": False,
            "fallback_used": True
        }
        report = assemble_final_report("t***t@example.com", facts, ai)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["email_masked"], "t***t@example.com")
        self.assertEqual(report["summary"]["breach_count"], 1)
        self.assertEqual(report["summary"]["risk_level"], "Moderate")
        self.assertEqual(report["summary"]["risk_score"], 45)
        self.assertEqual(len(report["breaches"]), 1)
        self.assertIn("attribution", report)


class TestFlaskEndpoints(unittest.TestCase):
    """Verifies HTTP API endpoints and rate limit security."""

    def setUp(self):
        self.client = app.test_client()
        with _rate_limit_lock:
            _ip_request_timestamps.clear()

    def tearDown(self):
        with _rate_limit_lock:
            _ip_request_timestamps.clear()

    def test_health_check(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["app"], "EchoRisk AI — Email Data Breach Tracker")

    def test_home_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"EchoRisk", res.data)
        self.assertIn(b"Breach Exposure Analytics", res.data)

    def test_breach_detail_page(self):
        res = self.client.get("/breach/Raaga")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Raaga", res.data)
        self.assertIn(b"Breach Dossier", res.data)

    def test_api_breach_detail(self):
        res = self.client.get("/api/breach/Raaga")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["breach_title"], "Raaga")
        self.assertIn("exposed_data", data)

    def test_scan_invalid_payloads(self):
        res = self.client.post("/api/scan", data="not json", content_type="text/plain")
        self.assertEqual(res.status_code, 400)

        # Non-dictionary JSON payload
        res = self.client.post("/api/scan", json=["invalid", "array"])
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["code"], "INVALID_PAYLOAD")

        res = self.client.post("/api/scan", json={"email": "invalid-email"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")

    def test_scan_mock_demo_addresses(self):
        # 1. Clean / safe demo
        res = self.client.post("/api/scan", json={"email": "safe@example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["summary"]["breach_count"], 0)
        self.assertEqual(data["summary"]["risk_level"], "Low")

        # 2. Compromised demo
        res = self.client.post("/api/scan", json={"email": "compromised@example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["summary"]["breach_count"], 3)
        self.assertTrue(data["summary"]["has_password_exposure"])
        self.assertTrue(len(data["breaches"]) == 3)

    def test_rate_limiting(self):
        for _ in range(30):
            res = self.client.post("/api/scan", json={"email": "safe@example.com"})
            self.assertEqual(res.status_code, 200)

        # 31st request should be rate-limited
        blocked_res = self.client.post("/api/scan", json={"email": "safe@example.com"})
        self.assertEqual(blocked_res.status_code, 429)
        data = blocked_res.get_json()
        self.assertEqual(data["code"], "RATE_LIMIT_EXCEEDED")

    def test_rate_limiting_ip_spoofing_blocked(self):
        # When TRUST_PROXY is false (default), spoofed X-Forwarded-For should not bypass rate limiting
        for _ in range(30):
            res = self.client.post(
                "/api/scan",
                json={"email": "safe@example.com"},
                headers={"X-Forwarded-For": "198.51.100.1"}
            )
            self.assertEqual(res.status_code, 200)

        blocked_res = self.client.post(
            "/api/scan",
            json={"email": "safe@example.com"},
            headers={"X-Forwarded-For": "203.0.113.99"}
        )
        self.assertEqual(blocked_res.status_code, 429)


if __name__ == "__main__":
    unittest.main()

