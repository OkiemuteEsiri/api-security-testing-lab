from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


@dataclass(frozen=True)
class Endpoint:
    path: str
    method: str
    auth_required: bool
    auth_scheme: str
    object_authorization: bool
    function_authorization: bool
    rate_limit_per_minute: int | None
    max_request_kb: int | None
    response_fields: tuple[str, ...]
    allowed_content_types: tuple[str, ...]
    owner: str
    internet_exposed: bool
    business_criticality: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Endpoint":
        required = {"path", "method", "auth_required", "auth_scheme", "object_authorization", "function_authorization", "response_fields", "allowed_content_types", "owner", "internet_exposed", "business_criticality"}
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"Endpoint missing required fields: {', '.join(missing)}")
        path = str(raw["path"]).strip()
        method = str(raw["method"]).upper().strip()
        if not path.startswith("/"):
            raise ValueError("Endpoint path must start with '/'")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"Unsupported HTTP method: {method}")
        criticality = str(raw["business_criticality"]).lower()
        if criticality not in {"low", "medium", "high", "critical"}:
            raise ValueError("business_criticality must be low, medium, high, or critical")
        rate = raw.get("rate_limit_per_minute")
        max_kb = raw.get("max_request_kb")
        if rate is not None and (not isinstance(rate, int) or rate <= 0):
            raise ValueError("rate_limit_per_minute must be a positive integer or null")
        if max_kb is not None and (not isinstance(max_kb, int) or max_kb <= 0):
            raise ValueError("max_request_kb must be a positive integer or null")
        return cls(path=path, method=method, auth_required=bool(raw["auth_required"]), auth_scheme=str(raw["auth_scheme"]).lower(), object_authorization=bool(raw["object_authorization"]), function_authorization=bool(raw["function_authorization"]), rate_limit_per_minute=rate, max_request_kb=max_kb, response_fields=tuple(str(v).lower() for v in raw["response_fields"]), allowed_content_types=tuple(str(v).lower() for v in raw["allowed_content_types"]), owner=str(raw["owner"]).strip(), internet_exposed=bool(raw["internet_exposed"]), business_criticality=criticality)


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    endpoint: str
    evidence: str
    remediation: str
    validation: str
    owasp_api: str
    attack: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"control_id": self.control_id, "title": self.title, "severity": self.severity, "endpoint": self.endpoint, "evidence": self.evidence, "remediation": self.remediation, "validation": self.validation, "owasp_api": self.owasp_api, "attack": list(self.attack)}
