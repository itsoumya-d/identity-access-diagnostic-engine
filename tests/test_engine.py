import pytest
from auth_diag.engine import (
    DiagnosticReport,
    OIDCValidator,
    SCIMLinter,
    RBACEvaluator,
)


def test_oidc_validator_valid():
    validator = OIDCValidator(
        expected_issuer="https://auth.enterprise.com",
        expected_audience="client_app_abc123",
    )
    claims = {
        "sub": "usr_998877",
        "iss": "https://auth.enterprise.com",
        "aud": "client_app_abc123",
        "exp": 1700001000,
        "nbf": 1700000000,
        "email": "engineer@enterprise.com",
        "email_verified": True,
    }
    report = validator.validate(claims, current_time=1700000500)
    assert report.valid
    assert len(report.issues) == 0


def test_oidc_validator_expired_and_mismatched():
    validator = OIDCValidator(
        expected_issuer="https://auth.enterprise.com",
        expected_audience="client_app_abc123",
    )
    claims = {
        "sub": "usr_998877",
        "iss": "https://rogue-idp.com",
        "aud": "wrong_app_id",
        "exp": 1700000000,
    }
    report = validator.validate(claims, current_time=1700001000)
    assert not report.valid
    assert any("Issuer mismatch" in msg for msg in report.issues)
    assert any("Audience mismatch" in msg for msg in report.issues)
    assert any("expired" in msg for msg in report.issues)


def test_scim_linter():
    linter = SCIMLinter()

    valid_payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user123@domain.com",
        "emails": [{"value": "user123@domain.com", "primary": True}],
    }
    report = linter.lint_user(valid_payload)
    assert report.valid

    invalid_payload = {
        "schemas": ["urn:some:other:schema"],
        "userName": "",
        "emails": [],
    }
    bad_report = linter.lint_user(invalid_payload)
    assert not bad_report.valid
    assert len(bad_report.issues) >= 2


def test_rbac_evaluator():
    role_defs = {
        "viewer": {"dashboards:read", "metrics:read"},
        "editor": {"dashboards:read", "dashboards:write", "metrics:read"},
        "admin": {"*:*"},
    }
    evaluator = RBACEvaluator(role_defs)

    # Viewer attempting write -> Denied with diagnostic
    report = evaluator.evaluate(assigned_roles=["viewer"], required_permission="dashboards:write")
    assert not report.valid
    assert "Missing required permission 'dashboards:write'" in report.issues[0]

    # Editor attempting write -> Passed
    ok_report = evaluator.evaluate(assigned_roles=["editor"], required_permission="dashboards:write")
    assert ok_report.valid

    # Admin wildcard -> Passed
    admin_report = evaluator.evaluate(assigned_roles=["admin"], required_permission="any:secret:action")
    assert admin_report.valid
