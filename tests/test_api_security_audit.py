import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from controls import audit_inventory, evaluate_endpoint
from io_utils import load_inventory
from models import Endpoint
from reporting import render_markdown
from scoring import posture_score, prioritized_findings


def endpoint(**overrides):
    raw={"path":"/api/v1/orders/{id}","method":"GET","auth_required":True,"auth_scheme":"bearer-jwt","object_authorization":True,"function_authorization":True,"rate_limit_per_minute":100,"max_request_kb":64,"response_fields":["id","status"],"allowed_content_types":["application/json"],"owner":"order-platform","internet_exposed":False,"business_criticality":"medium"}
    raw.update(overrides)
    return Endpoint.from_dict(raw)

class ApiSecurityAuditTests(unittest.TestCase):
    def test_bola_control(self): self.assertIn("API-001",{f.control_id for f in evaluate_endpoint(endpoint(object_authorization=False))})
    def test_weak_authentication(self): self.assertIn("API-002",{f.control_id for f in evaluate_endpoint(endpoint(auth_scheme="basic"))})
    def test_function_authorization_for_admin_route(self): self.assertIn("API-003",{f.control_id for f in evaluate_endpoint(endpoint(path="/api/v1/admin/users",method="POST",function_authorization=False))})
    def test_resource_guardrails(self): self.assertIn("API-004",{f.control_id for f in evaluate_endpoint(endpoint(rate_limit_per_minute=None,max_request_kb=None))})
    def test_sensitive_response_fields(self): self.assertIn("API-005",{f.control_id for f in evaluate_endpoint(endpoint(response_fields=["id","token"]))})
    def test_risky_content_type(self): self.assertIn("API-006",{f.control_id for f in evaluate_endpoint(endpoint(allowed_content_types=["application/json","application/xml"]))})
    def test_secure_endpoint_has_no_findings(self): self.assertEqual(evaluate_endpoint(endpoint()),[])
    def test_duplicate_inventory_is_rejected(self):
        raw=[endpoint().__dict__,endpoint().__dict__]
        for item in raw:
            item["response_fields"]=list(item["response_fields"]); item["allowed_content_types"]=list(item["allowed_content_types"])
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"inventory.json"; path.write_text(json.dumps(raw),encoding="utf-8")
            with self.assertRaises(ValueError): load_inventory(path)
    def test_posture_score_decreases_with_findings(self): self.assertLess(posture_score(audit_inventory([endpoint(object_authorization=False)]),1),100)
    def test_internet_exposure_breaks_priority_tie(self):
        internal=endpoint(path="/a/{id}",object_authorization=False); external=endpoint(path="/b/{id}",object_authorization=False,internet_exposed=True)
        ordered=prioritized_findings(audit_inventory([internal,external]),[internal,external]); self.assertEqual(ordered[0].endpoint,"GET /b/{id}")
    def test_markdown_report_contains_validation(self):
        e=endpoint(object_authorization=False); report=render_markdown([e],audit_inventory([e])); self.assertIn("Remediation & Validation",report); self.assertIn("API-001",report)

if __name__=="__main__": unittest.main()
