# API Security Testing Lab

A safe, recruiter-facing API security engineering project focused on authorization, authentication, input validation, data exposure, rate limiting, and remediation verification using synthetic test cases.

## Objectives

- Model API security checks without targeting real systems.
- Map tests to common API risks such as broken object-level authorization, broken authentication, excessive data exposure, unrestricted resource consumption, and security misconfiguration.
- Convert findings into reproducible evidence and remediation guidance.
- Demonstrate validation after fixes rather than stopping at initial discovery.

## Test Model

The project uses synthetic endpoint definitions and expected security controls. The analyzer flags missing authorization, weak authentication assumptions, absent rate limits, and excessive response fields based on declared metadata.

## Repository Structure

- `data/synthetic_api_inventory.json` - synthetic API endpoint catalogue
- `src/api_security_audit.py` - defensive metadata audit engine
- `tests/test_api_security_audit.py` - unit tests
- `docs/testing-methodology.md` - scoped assessment and remediation-validation methodology

## Usage

```bash
python src/api_security_audit.py data/synthetic_api_inventory.json
python -m unittest discover -s tests
```

## Security Focus

| Area | Example control |
| --- | --- |
| Object authorization | Per-object ownership/entitlement check |
| Authentication | Strong token validation and expiry |
| Resource consumption | Rate limiting and request-size limits |
| Data exposure | Response minimization and field-level filtering |
| Misconfiguration | Secure defaults, explicit methods, logging |

## Safety

All endpoints, users, identifiers, and findings are synthetic. This repository does not contain production targets, credentials, exploit automation, destructive payloads, or instructions for bypassing live security controls.
