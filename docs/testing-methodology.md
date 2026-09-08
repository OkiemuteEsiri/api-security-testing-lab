# API Security Testing Methodology

## Scope and Preconditions

Testing is limited to explicitly authorized lab systems or synthetic inventories. Define the API version, authentication model, test accounts, permitted methods, rate limits, data classifications, and stop conditions before assessment.

## Assessment Areas

### Authorization
- Verify object-level access decisions are enforced server-side.
- Verify function-level authorization is role-aware.
- Confirm identifier changes do not alter authorization outcomes.

### Authentication
- Validate token signature, issuer, audience, expiry, and revocation behavior.
- Verify privileged functions require appropriate authentication strength.

### Data Exposure
- Review response schemas for unnecessary sensitive fields.
- Confirm error responses avoid secrets, stack traces, and internal identifiers.

### Resource Controls
- Confirm request-size, pagination, concurrency, and rate-limit controls.
- Verify expensive operations cannot be invoked without appropriate restrictions.

### Configuration and Logging
- Restrict unnecessary HTTP methods.
- Apply secure headers where relevant.
- Generate sufficient security telemetry for authentication failures, authorization denials, and administrative changes.

## Finding Quality

Each finding should include affected endpoint, precondition, observed control weakness, security impact, risk rating, reproducible evidence reference, recommended remediation, and validation criteria.

## Remediation Validation

After a fix, repeat the original security test and at least one negative-control test. Confirm the unauthorized action is denied, legitimate access continues to function, logging captures the event, and no equivalent path remains through another endpoint or method.
