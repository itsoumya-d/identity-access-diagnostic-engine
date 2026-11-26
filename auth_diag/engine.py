from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Set


@dataclass
class DiagnosticReport:
    valid: bool
    issues: List[str] = field(default_factory=list)
    remediations: List[str] = field(default_factory=list)

    def add_issue(self, msg: str, fix: str) -> None:
        self.valid = False
        self.issues.append(msg)
        self.remediations.append(fix)


class OIDCValidator:
    """Validates OpenID Connect / SAML claim sets against strict enterprise standards."""

    def __init__(self, expected_issuer: str, expected_audience: str, clock_skew_sec: int = 60):
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.clock_skew_sec = clock_skew_sec

    def validate(self, claims: Dict[str, Any], current_time: Optional[float] = None) -> DiagnosticReport:
        report = DiagnosticReport(valid=True)
        now = current_time if current_time is not None else time.time()

        # 1. Subject Identifier
        if not claims.get("sub"):
            report.add_issue("Missing 'sub' (subject identifier) in token claims.", "Configure Identity Provider to map a permanent unique user subject.")

        # 2. Issuer Validation
        iss = claims.get("iss")
        if not iss:
            report.add_issue("Missing 'iss' (issuer) claim.", "Ensure IDP token generator includes canonical issuer URL.")
        elif iss != self.expected_issuer:
            report.add_issue(f"Issuer mismatch: expected '{self.expected_issuer}', got '{iss}'.", "Update IDP configuration or trust relationship in account settings.")

        # 3. Audience Validation
        aud = claims.get("aud")
        if not aud:
            report.add_issue("Missing 'aud' (audience) claim.", "Set client ID / application ID in the IDP token audience mapping.")
        elif isinstance(aud, str) and aud != self.expected_audience:
            report.add_issue(f"Audience mismatch: expected '{self.expected_audience}', got '{aud}'.", "Confirm client application ID matches registered SSO audience.")
        elif isinstance(aud, list) and self.expected_audience not in aud:
            report.add_issue(f"Target audience '{self.expected_audience}' not present in audience list: {aud}.", "Include target application ID in allowed audiences.")

        # 4. Expiration & Not Before
        exp = claims.get("exp")
        if exp is not None:
            if now > exp + self.clock_skew_sec:
                report.add_issue(f"Token has expired at {exp} (current time {int(now)}, skew {self.clock_skew_sec}s).", "Refresh SSO session or extend token lifetime in IDP.")
        else:
            report.add_issue("Missing 'exp' (expiration time) claim.", "Configure mandatory token expiration in IDP.")

        nbf = claims.get("nbf")
        if nbf is not None and now < nbf - self.clock_skew_sec:
            report.add_issue(f"Token is not yet valid (nbf: {nbf}, current: {int(now)}).", "Synchronize server system clocks (NTP) to eliminate clock skew.")

        # 5. Email claim
        email = claims.get("email")
        if email and claims.get("email_verified") is False:
            report.add_issue(f"Email '{email}' is marked unverified by identity provider.", "Require email verification before granting enterprise organization access.")

        return report


class SCIMLinter:
    """Lints SCIM 2.0 User and Group provisioning payloads for enterprise schema compliance."""

    USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"

    def lint_user(self, payload: Dict[str, Any]) -> DiagnosticReport:
        report = DiagnosticReport(valid=True)

        schemas = payload.get("schemas", [])
        if self.USER_SCHEMA not in schemas:
            report.add_issue(f"Missing core user schema '{self.USER_SCHEMA}' in schemas list.", "Ensure SCIM bridge requests include standard RFC 7643 core schema header.")

        user_name = payload.get("userName")
        if not user_name:
            report.add_issue("Missing required attribute 'userName'.", "Map enterprise primary identifier to SCIM 'userName'.")

        emails = payload.get("emails", [])
        if not isinstance(emails, list) or len(emails) == 0:
            report.add_issue("Missing or empty 'emails' array in SCIM user resource.", "Provide at least one primary email address in provisioning configuration.")
        else:
            has_primary = any(e.get("primary") is True for e in emails if isinstance(e, dict))
            if not has_primary and len(emails) > 1:
                report.add_issue("Multiple emails provided without explicit 'primary: true' flag.", "Designate one email entry as primary to prevent identity routing ambiguity.")

        return report


class RBACEvaluator:
    """Evaluates multi-tenant RBAC policies and pinpoints authorization denial causes."""

    def __init__(self, role_permissions: Dict[str, Set[str]]):
        self.role_permissions = role_permissions

    def evaluate(self, assigned_roles: List[str], required_permission: str) -> DiagnosticReport:
        report = DiagnosticReport(valid=True)
        aggregated_perms: Set[str] = set()

        unknown_roles = [r for r in assigned_roles if r not in self.role_permissions]
        if unknown_roles:
            report.add_issue(f"User is assigned unmapped roles: {unknown_roles}.", "Define missing roles or prune legacy assignments from IdP group mapping.")

        for role in assigned_roles:
            if role in self.role_permissions:
                aggregated_perms.update(self.role_permissions[role])

        if required_permission not in aggregated_perms and "*:*" not in aggregated_perms:
            report.add_issue(
                f"Missing required permission '{required_permission}'. Assigned roles {assigned_roles} grant: {sorted(list(aggregated_perms)) or 'none'}.",
                f"Grant role containing '{required_permission}' or elevate user to required permission tier."
            )

        return report
