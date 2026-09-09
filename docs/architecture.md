# Architecture

## Purpose

This lab models a safe API security review pipeline around **declared endpoint metadata** rather than live attack traffic. It supports secure-design review, CI security gates, and remediation tracking without sending requests to production systems.

## Data Flow

```text
Synthetic API inventory
        |
        v
Schema validation / normalization
        |
        v
Defensive controls engine
        |
        +--> OWASP API risk mapping
        +--> MITRE ATT&CK contextual mapping
        |
        v
Prioritization + posture metrics
        |
        v
JSON / Markdown evidence report
        |
        v
Remediation -> re-run -> validation
```

## Modules

- `models.py` defines immutable endpoint and finding contracts.
- `io_utils.py` validates inventory shape and rejects duplicate method/path pairs.
- `controls.py` implements deterministic security controls.
- `scoring.py` provides severity/context prioritization and a bounded posture score.
- `reporting.py` renders human-readable evidence and closure guidance.
- `cli.py` provides a repeatable local interface.

## Trust Boundaries

No network client is implemented. Input is local JSON. The lab does not perform credential attacks, authorization bypass attempts, fuzzing against real hosts, or destructive testing.

## Design Decisions

1. **Fail closed on malformed inventory.** Invalid records raise explicit errors rather than being silently skipped.
2. **Evidence before severity.** Findings record the declared control gap that triggered them.
3. **Context affects ordering, not facts.** Internet exposure and business criticality prioritize findings but do not manufacture vulnerability evidence.
4. **Validation is first-class.** Every control includes a specific re-test objective.
