# API Security Testing Lab

A recruiter-facing **API Security Engineering** project that turns synthetic API inventory metadata into deterministic security findings, prioritization, remediation guidance, and revalidation evidence.

This project is deliberately defensive: it evaluates local JSON metadata and does **not** send attack traffic, target production APIs, use credentials, or automate exploitation.

## Problem Statement

API reviews often fail when they stop at scanner observations. Engineering teams need a repeatable way to connect endpoint ownership and business context to authorization, authentication, data-minimization, parser-surface, and resource-consumption controls—and then verify remediation.

This lab demonstrates that workflow using safe synthetic inputs.

## Architecture

```text
data/synthetic_api_inventory.json
              |
              v
       io_utils.py
 validation + normalization
              |
              v
        controls.py
 deterministic control checks
              |
              +--> OWASP API mappings
              +--> MITRE ATT&CK context
              |
              v
         scoring.py
 severity + exposure + criticality
              |
              v
        reporting.py
 Markdown / JSON evidence
              |
              v
 remediation -> inventory update -> re-run
```

See `docs/architecture.md` for design details.

## Implemented Controls

| ID | Security control | Risk class |
| --- | --- | --- |
| API-001 | Object-level authorization | OWASP API1:2023 BOLA |
| API-002 | Authentication scheme quality | OWASP API2:2023 Broken Authentication |
| API-003 | Function-level authorization | OWASP API5:2023 BFLA |
| API-004 | Rate/payload guardrails | OWASP API4:2023 Resource Consumption |
| API-005 | Sensitive response minimization | OWASP API3:2023 Object Property Authorization |
| API-006 | Content-type minimization | OWASP API8:2023 Security Misconfiguration |
| API-007 | Internet-facing ownership | OWASP API9:2023 Inventory Management |

## Repository Structure

```text
.github/workflows/ci.yml
data/synthetic_api_inventory.json
docs/architecture.md
docs/remediation-validation.md
docs/testing-methodology.md
reports/example-assessment.md
src/api_security_audit.py
src/cli.py
src/controls.py
src/io_utils.py
src/models.py
src/reporting.py
src/scoring.py
tests/test_api_security_audit.py
```

## Usage

```bash
python src/cli.py data/synthetic_api_inventory.json --format markdown
python src/cli.py data/synthetic_api_inventory.json --format json
python src/cli.py data/synthetic_api_inventory.json --output assessment.md
python -m unittest discover -s tests -v
```

No third-party Python packages are required.

## Prioritization Design

The engine separates **finding evidence** from **business context**. Severity reflects the control gap, while internet exposure and business criticality influence ordering. The posture score is a bounded lab metric for comparing synthetic inventories; it is not a compliance certification or breach-likelihood model.

## MITRE ATT&CK Context

| Technique | Relevance |
| --- | --- |
| T1078 — Valid Accounts | Authentication/authorization failures can increase impact after account access |
| T1190 — Exploit Public-Facing Application | Context for weaknesses on exposed application/API surfaces |
| T1499 — Endpoint Denial of Service | Context for missing resource-consumption guardrails |

ATT&CK mappings provide threat context only and are not claims of adversary activity.

## Remediation and Validation

Every finding includes both a remediation action and a validation objective. The expected workflow is:

1. assign the finding to the API owner;
2. implement the control in code, gateway, or identity policy;
3. update the approved inventory/specification;
4. re-run the assessment;
5. verify the original control ID closes;
6. perform authorized regression/integration tests;
7. preserve evidence for closure.

See `docs/remediation-validation.md`.

## CI/CD Security Quality

The GitHub Actions workflow uses read-only repository permissions and performs source compilation, unit-test execution, a synthetic end-to-end report-generation smoke test, and output validation. CI success demonstrates only that these repository checks passed for a commit; it does not validate a live API.

## Skills Demonstrated

- API security engineering
- OWASP API Security Top 10 mapping
- authorization and authentication control design
- exposure/context-aware prioritization
- secure data-model validation
- deterministic security automation
- remediation and revalidation workflow design
- evidence-oriented reporting
- Python unit testing
- GitHub Actions security-quality gates
- MITRE ATT&CK contextual mapping

## Limitations

- No live API requests are sent.
- No DAST, fuzzing, credential testing, or exploit automation is implemented.
- Metadata declarations can drift from implementation.
- The control set is intentionally focused rather than a complete verification standard.
- Production adoption would require approved integration tests, code review, gateway/identity configuration review, telemetry validation, and organization-specific risk criteria.

## Roadmap

- ingest OpenAPI 3.x documents into the canonical endpoint model;
- add schema-diff based remediation verification;
- add policy-as-code export for CI approval gates;
- enrich ownership/SLA routing;
- generate SARIF for developer workflow integration;
- add contract tests for authentication/authorization invariants.

## Safety

All endpoint names, identities, findings, and configuration in this repository are synthetic. There are no real credentials, employer/client data, production targets, unsafe offensive payloads, or claims of real compromise.
