from __future__ import annotations

import json
import sys
from pathlib import Path

SENSITIVE_FIELDS = {"internal_notes", "ssn", "password", "token", "secret"}


def load_inventory(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("Inventory must be a list of endpoint definitions")
    return data


def audit_endpoint(endpoint: dict) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    name = f"{endpoint.get('method', 'UNKNOWN')} {endpoint.get('endpoint', '<missing>')}"

    if endpoint.get("auth_required") and not endpoint.get("object_authorization") and "{id}" in endpoint.get("endpoint", ""):
        findings.append({
            "endpoint": name,
            "risk": "Broken Object Level Authorization",
            "severity": "High",
            "remediation": "Enforce server-side authorization for every requested object.",
        })

    if not endpoint.get("rate_limit"):
        findings.append({
            "endpoint": name,
            "risk": "Unrestricted Resource Consumption",
            "severity": "Medium",
            "remediation": "Apply rate, concurrency, and request-size controls appropriate to the endpoint.",
        })

    exposed = sorted(set(endpoint.get("response_fields", [])) & SENSITIVE_FIELDS)
    if exposed:
        findings.append({
            "endpoint": name,
            "risk": "Excessive Data Exposure",
            "severity": "Medium",
            "remediation": f"Remove unnecessary sensitive response fields: {', '.join(exposed)}.",
        })

    return findings


def audit_inventory(inventory: list[dict]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for endpoint in inventory:
        findings.extend(audit_endpoint(endpoint))
    return findings


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python src/api_security_audit.py <inventory.json>")
    findings = audit_inventory(load_inventory(sys.argv[1]))
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
