# API Security Testing Lab

A recruiter-facing **API Security Engineering** project that turns synthetic API inventory metadata into deterministic security findings, contextual prioritization, remediation guidance, and revalidation evidence.

This project is deliberately defensive: it evaluates local JSON metadata and does **not** send attack traffic, target production APIs, use credentials, or automate exploitation.

## Recruiter Quick Review

For a focused technical review, start with:

1. `src/controls.py` — implemented authorization, authentication, availability, data-minimization, parser-surface, and ownership controls;
2. `src/scoring.py` — contextual prioritization logic;
3. `tests/test_api_security_audit.py` — validation coverage;
4. `reports/example-assessment.md` — synthetic analyst-facing output;
5. `docs/control-validation-matrix.md` — control-to-evidence and revalidation traceability;
6. `docs/recruiter-review.md` — capability-to-evidence map and review sequence.

| Recruiter signal | Evidence |
| --- | --- |
| Security engineering | deterministic control engine and canonical data model |
| API security | OWASP API Security Top 10-aligned control checks |
| Risk prioritization | severity, exposure, and business-criticality separation |
| Remediation discipline | explicit closure and revalidation workflow |
| Secure automation | fail-closed input validation and deterministic output |
| Engineering quality | unit tests, offline CLI, example report, and GitHub Actions |
| Threat-informed design | MITRE ATT&CK used as defensive context, not compromise evidence |

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
 remediation -> inventory update -> re-run -> evidence
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

The detailed validation expectations for each control are documented in `docs/control-validation-matrix.md`.

## Repository Structure

```text
.github/workflows/ci.yml
data/synthetic_api_inventory.json
docs/architecture.md
docs/control-validation-matrix.md
docs/recruiter-review.md
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

The engine separates **finding evidence** from **business context**. Severity reflects the control gap, while internet exposure and business criticality influence ordering. The posture score is a bounded lab metric for comparing synthetic inventories; it is not a compliance certification, exploitability score, or breach-likelihood model.

This separation is intentional: business context can increase remediation urgency without rewriting the underlying technical observation.

## MITRE ATT&CK Context

| Technique | Relevance |
| --- | --- |
| T1078 — Valid Accounts | Authentication/authorization failures can increase impact after account access |
| T1190 — Exploit Public-Facing Application | Context for weaknesses on exposed application/API surfaces |
| T1499 — Endpoint Denial of Service | Context for missing resource-consumption guardrails |

ATT&CK mappings provide defensive threat context only. They are **not** claims of exploitation, compromise, adversary intent, attribution, or incident status.

## Remediation and Revalidation

Every finding includes both a remediation action and a validation objective. The expected workflow is:

1. assign the finding to the accountable API owner;
2. confirm the intended security contract;
3. implement the control in application code, gateway configuration, or identity policy;
4. retain implementation evidence and the associated change reference;
5. update the approved inventory/specification;
6. re-run the assessment and confirm the original control condition no longer appears;
7. perform authorized regression/integration testing for the affected security invariant;
8. retain post-change evidence for closure.

A ticket closure alone is not technical validation. Risk acceptance is also distinct from remediation: an approved exception may alter governance status, but it does not remove the technical exposure.

See `docs/remediation-validation.md` and `docs/control-validation-matrix.md`.

## CI/CD Security Quality

The GitHub Actions workflow uses read-only repository permissions and performs source compilation, unit-test execution, a synthetic end-to-end report-generation smoke test, and output validation.

A green workflow is meaningful only for the **exact commit** that produced it. CI success demonstrates that repository checks passed for that commit; it does not validate a live API or production environment.

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

## Documentation

- `docs/recruiter-review.md` — fast technical review path and capability-to-evidence map
- `docs/architecture.md` — components, boundaries, and data flow
- `docs/testing-methodology.md` — assessment method and control logic
- `docs/control-validation-matrix.md` — control, evidence, remediation, and revalidation matrix
- `docs/remediation-validation.md` — technical closure workflow
- `reports/example-assessment.md` — example synthetic assessment output

## Limitations

- No live API requests are sent.
- No DAST, fuzzing, credential testing, or exploit automation is implemented.
- Metadata declarations can drift from implementation.
- The control set is intentionally focused rather than a complete verification standard.
- The scoring model is a deterministic prioritization aid, not a quantitative prediction of compromise.
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
