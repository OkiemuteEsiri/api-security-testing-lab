# Recruiter Review Guide

This repository is designed to be reviewed as an **API Security Engineering** project rather than as an offensive exploitation lab. It demonstrates how synthetic API inventory metadata can be converted into deterministic findings, prioritized by business context, and carried through remediation and revalidation.

## Five-Minute Review Path

1. **README.md** — problem statement, architecture, scope, and safety boundaries.
2. **src/models.py** — canonical endpoint and finding data models.
3. **src/controls.py** — deterministic API security control checks.
4. **src/scoring.py** — contextual prioritization logic.
5. **src/reporting.py** — evidence-oriented output generation.
6. **tests/test_api_security_audit.py** — positive and negative validation coverage.
7. **reports/example-assessment.md** — synthetic analyst-facing output.
8. **docs/control-validation-matrix.md** — control, evidence, remediation, and revalidation traceability.

## Capability-to-Evidence Map

| Capability | Repository evidence |
| --- | --- |
| API security assessment design | `src/controls.py`, `docs/testing-methodology.md` |
| Authorization and authentication review | API-001, API-002, API-003 controls |
| Exposure-aware prioritization | `src/scoring.py` |
| Secure input handling | `src/io_utils.py`, `src/models.py` |
| Evidence-oriented reporting | `src/reporting.py`, `reports/example-assessment.md` |
| Remediation governance | `docs/remediation-validation.md` |
| Repeatable verification | `tests/test_api_security_audit.py`, `.github/workflows/ci.yml` |
| Threat-context mapping | OWASP API Security Top 10 and MITRE ATT&CK context in project docs |

## Engineering Questions This Project Demonstrates

- How should API findings be separated from business-risk context?
- How can authorization, authentication, resource-consumption, data-minimization, and inventory controls be represented deterministically?
- What evidence should be required before a finding is considered remediated?
- How should ATT&CK mappings be used without overstating compromise or attribution?
- How can a safe offline assessor support a future CI/CD or policy-as-code integration?

## Security Boundaries

The project does **not** perform live exploitation, fuzzing, credential attacks, production scanning, authorization bypass attempts, or destructive testing. All API names, identities, metadata, findings, and outputs are synthetic.

## CI Interpretation

A successful GitHub Actions run indicates that repository compilation, unit tests, and the synthetic smoke assessment passed for that exact commit. It is not evidence that a live API, production environment, or external target was tested.
