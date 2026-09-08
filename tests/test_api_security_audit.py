import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from api_security_audit import audit_endpoint, audit_inventory


class ApiSecurityAuditTests(unittest.TestCase):
    def test_flags_bola_for_object_endpoint_without_object_check(self):
        endpoint = {
            "endpoint": "/api/v1/profile/{id}",
            "method": "GET",
            "auth_required": True,
            "object_authorization": False,
            "rate_limit": True,
            "response_fields": ["id"],
        }
        risks = {f["risk"] for f in audit_endpoint(endpoint)}
        self.assertIn("Broken Object Level Authorization", risks)

    def test_flags_sensitive_response_field(self):
        endpoint = {
            "endpoint": "/api/v1/profile/{id}",
            "method": "GET",
            "auth_required": True,
            "object_authorization": True,
            "rate_limit": True,
            "response_fields": ["id", "internal_notes"],
        }
        risks = {f["risk"] for f in audit_endpoint(endpoint)}
        self.assertIn("Excessive Data Exposure", risks)

    def test_secure_metadata_returns_no_findings(self):
        endpoint = {
            "endpoint": "/api/v1/orders/{id}",
            "method": "GET",
            "auth_required": True,
            "object_authorization": True,
            "rate_limit": True,
            "response_fields": ["id", "status"],
        }
        self.assertEqual(audit_inventory([endpoint]), [])


if __name__ == "__main__":
    unittest.main()
