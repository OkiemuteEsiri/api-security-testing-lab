# API Control Validation Matrix

This matrix links each implemented control to its risk condition, expected remediation evidence, and the minimum revalidation condition required for technical closure.

| Control | Risk condition | Primary impact | Remediation evidence | Revalidation condition | Threat context |
| --- | --- | --- | --- | --- | --- |
| API-001 Object-level authorization | Object access is not explicitly constrained by subject entitlement | Unauthorized data access or modification | Server-side authorization rule, code/config review, approved access model | Authorized synthetic identity A cannot access identity B's object outside its entitlement | OWASP API1:2023; ATT&CK T1078 context |
| API-002 Authentication scheme quality | Weak, missing, or inappropriate authentication control | Account/session abuse and unauthorized API access | Identity/gateway configuration, approved authentication standard, change reference | Endpoint rejects unauthenticated or disallowed authentication modes and preserves expected authorized flow | OWASP API2:2023; ATT&CK T1078 context |
| API-003 Function-level authorization | Sensitive operation lacks role/permission enforcement | Unauthorized privileged function execution | Role-to-function policy, server-side enforcement evidence, code/config review | Lower-privileged synthetic role cannot invoke privileged operation | OWASP API5:2023; ATT&CK T1078 context |
| API-004 Resource-consumption guardrails | Rate, size, timeout, concurrency, or expensive-operation limits are absent | Availability degradation or resource exhaustion | Gateway/application policy with bounded thresholds and ownership | Authorized bounded tests above policy are rejected predictably without destabilizing the service | OWASP API4:2023; ATT&CK T1499 context |
| API-005 Sensitive response minimization | Response exposes unnecessary sensitive properties | Excessive disclosure and privacy impact | Approved response schema, field-level authorization/minimization change | Post-fix response contract excludes unnecessary sensitive fields for the tested role | OWASP API3:2023 |
| API-006 Content-type minimization | Endpoint accepts unnecessary parser/content types | Expanded parser and misconfiguration attack surface | Explicit allowed-content configuration and endpoint contract | Unsupported content types are rejected while approved types continue to work | OWASP API8:2023; ATT&CK T1190 context where exposed |
| API-007 Internet-facing ownership | Exposed endpoint lacks accountable owner/inventory quality | Delayed remediation, unmanaged exposure, weak lifecycle control | Named service owner, inventory record, review cadence, retirement/escalation path | Inventory contains accountable owner and exposure classification and remains consistent with approved deployment | OWASP API9:2023 |

## Evidence Quality Levels

1. **Administrative evidence only** — ticket or statement that work was completed. Insufficient for technical closure.
2. **Implementation evidence** — code, gateway, identity, or configuration change exists, but no post-change verification is recorded.
3. **Revalidation evidence** — the original control condition is re-tested and the expected secure behavior is observed.
4. **Sustainable validation** — revalidation is repeatable through automated tests, policy checks, or governed review with retained evidence.

## Closure Rule

A finding should not be treated as technically closed merely because a change request or exception record exists. Technical closure requires evidence that the original control condition no longer reproduces under an approved test method.

Risk acceptance is separate from remediation. An accepted exception may change governance status, but it does not make the technical exposure disappear.

## ATT&CK Interpretation

ATT&CK entries in this repository provide defensive threat context only. They do not establish exploitation, compromise, adversary intent, attribution, or incident status.
