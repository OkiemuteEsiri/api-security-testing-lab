from __future__ import annotations

from models import Endpoint, Finding

SENSITIVE_FIELDS = {"password","secret","token","access_token","refresh_token","ssn","national_id","internal_notes","api_key"}
OBJECT_MARKERS = ("{id}", "{user_id}", "{account_id}", "{order_id}")
ADMIN_MARKERS = ("/admin", "/privileged", "/management")

def evaluate_endpoint(endpoint: Endpoint) -> list[Finding]:
    name = f"{endpoint.method} {endpoint.path}"
    findings: list[Finding] = []
    if endpoint.auth_required and any(m in endpoint.path for m in OBJECT_MARKERS) and not endpoint.object_authorization:
        findings.append(Finding("API-001","Object-level authorization not declared","High",name,"Object-addressable endpoint requires authentication but declares no per-object authorization check.","Enforce server-side ownership or entitlement checks for every object access.","Re-test with two synthetic principals and verify cross-object access is denied.","API1:2023 Broken Object Level Authorization",("T1078",)))
    if endpoint.auth_required and endpoint.auth_scheme in {"none","basic","api-key-query"}:
        findings.append(Finding("API-002","Weak authentication scheme","High",name,f"Declared authentication scheme is '{endpoint.auth_scheme}'.","Use a centrally validated token/session design with expiry, audience/issuer checks, and secret-safe transport.","Verify invalid, expired, and wrong-audience synthetic tokens are rejected.","API2:2023 Broken Authentication",("T1078",)))
    if any(marker in endpoint.path for marker in ADMIN_MARKERS) and not endpoint.function_authorization:
        findings.append(Finding("API-003","Function-level authorization not declared","High",name,"Administrative route lacks an explicit function-level authorization control.","Enforce role/permission checks server-side and deny by default.","Verify a non-privileged synthetic identity receives a denial response.","API5:2023 Broken Function Level Authorization",("T1078",)))
    if endpoint.rate_limit_per_minute is None or endpoint.max_request_kb is None:
        missing=[]
        if endpoint.rate_limit_per_minute is None: missing.append("rate limit")
        if endpoint.max_request_kb is None: missing.append("request-size limit")
        findings.append(Finding("API-004","Resource-consumption guardrail missing","Medium",name,"Missing declared "+" and ".join(missing)+".","Set endpoint-appropriate rate, concurrency, payload-size, and timeout controls.","Run bounded synthetic load/size tests and verify requests beyond policy are rejected safely.","API4:2023 Unrestricted Resource Consumption",("T1499",)))
    exposed=sorted(set(endpoint.response_fields)&SENSITIVE_FIELDS)
    if exposed:
        findings.append(Finding("API-005","Sensitive response fields declared","High",name,"Response model exposes: "+", ".join(exposed)+".","Minimize response schemas and apply field-level authorization before serialization.","Re-run schema checks and confirm unnecessary sensitive fields are absent.","API3:2023 Broken Object Property Level Authorization",()))
    risky=sorted(set(endpoint.allowed_content_types)&{"text/html","application/xml","text/xml"})
    if risky:
        findings.append(Finding("API-006","Broad or risky content type accepted","Medium",name,"Declared accepted content types include: "+", ".join(risky)+".","Allow only content types required by the business contract and parse with safe libraries.","Verify unsupported content types are rejected before business processing.","API8:2023 Security Misconfiguration",("T1190",)))
    if endpoint.internet_exposed and not endpoint.owner:
        findings.append(Finding("API-007","Internet-facing endpoint has no owner","Medium",name,"Endpoint is internet exposed but ownership metadata is blank.","Assign an accountable service owner and integrate ownership into remediation routing.","Confirm the owner is present in inventory and receives test findings.","API9:2023 Improper Inventory Management",()))
    return findings

def audit_inventory(endpoints: list[Endpoint]) -> list[Finding]:
    findings=[]
    for endpoint in endpoints:
        findings.extend(evaluate_endpoint(endpoint))
    return findings
