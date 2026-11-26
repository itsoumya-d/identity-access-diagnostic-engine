# Identity & Access Diagnostic Engine

Enterprise identity and authorization diagnostic engine in Python. Analyzes OIDC claims, SAML assertions, SCIM 2.0 provisioning payloads, and RBAC permission hierarchies to isolate enterprise login failures and permission mismatches.

## Features

- **OIDC & SAML Claim Validation**: Audits token assertions against standard audience, issuer, expiry, and required identity claims.
- **SCIM 2.0 Schema Linter**: Verifies enterprise user and group provisioning schemas to catch synchronization drift.
- **RBAC Policy Diagnostic**: Traces permission evaluation across multi-tenant role hierarchies and identifies the exact source of authorization denials.
- **Zero Dependencies**: Pure Python standard library implementation, fully tested with `pytest`.

## Usage

```bash
pip install -e .
pytest
```
