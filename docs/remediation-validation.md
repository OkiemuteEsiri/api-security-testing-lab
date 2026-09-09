# Remediation and Validation Workflow

1. Assign each finding to the accountable API/service owner.
2. Confirm the expected security contract with engineering.
3. Implement the control in application, gateway, or identity policy as appropriate.
4. Update the controlled inventory/specification.
5. Re-run the assessor.
6. Confirm the original control ID no longer appears.
7. Perform regression testing for adjacent authorization, authentication, and availability behavior.
8. Preserve closure evidence.

## API-001 — Object authorization

**Remediation:** enforce ownership/entitlement checks server-side after authentication and before data access.

**Validation:** use two authorized synthetic identities in an approved test environment and verify identity A cannot retrieve identity B's object.

## API-004 — Resource consumption

**Remediation:** implement request-size, rate, concurrency, timeout, and expensive-operation limits appropriate to the endpoint.

**Validation:** use bounded synthetic tests below and just above policy and confirm excess requests fail predictably without application instability.

## API-005 — Sensitive response fields

**Remediation:** remove unnecessary sensitive attributes and apply field-level authorization.

**Validation:** compare the post-fix response contract with the approved schema and confirm sensitive fields are absent unless explicitly required and authorized.
