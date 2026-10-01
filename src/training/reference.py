# Attack reference library - the defensive knowledge base.
#
# One TechniqueReference per identity / M365 attack the engine cares about,
# spanning initial access (the existing telemetry modules) and post-breach
# activity (persistence, collection, privilege escalation, exfiltration).
#
# Each entry answers the questions an on-call engineer actually asks at 2am:
#   - What is this technique and what is the attacker trying to achieve?
#   - Which audit log will it appear in, and under what operation name?
#   - What separates it from benign activity (and what causes false positives)?
#   - What do I paste into Sentinel / Defender to hunt for it?
#   - What are my response steps?
#
# The detection queries are illustrative starting points - tune table/column
# names to your own workspace (Sentinel OfficeActivity vs. Defender CloudAppEvents,
# etc.) before relying on them.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionQuery:
    platform: str          # e.g. "Microsoft Sentinel (KQL)"
    query: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"platform": self.platform, "query": self.query, "note": self.note}


@dataclass
class TechniqueReference:
    key: str
    title: str
    phase: str                     # "Initial Access" | "Post-Breach"
    mitre_technique: str
    mitre_name: str
    tactic: str
    summary: str
    attacker_goal: str
    log_sources: list[str] = field(default_factory=list)
    audit_operations: list[str] = field(default_factory=list)
    key_fields: list[dict[str, str]] = field(default_factory=list)
    what_to_look_for: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    detections: list[DetectionQuery] = field(default_factory=list)
    response_steps: list[str] = field(default_factory=list)
    saas_alerts_event: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "detections"}
        d["detections"] = [q.to_dict() for q in self.detections]
        return d


# ---------------------------------------------------------------------------
# Initial-access techniques (the existing telemetry modules)
# ---------------------------------------------------------------------------

_AUTH_FAILURE = TechniqueReference(
    key="auth_failure",
    title="Password Spraying / Repeated Sign-in Failures",
    phase="Initial Access",
    mitre_technique="T1110.003",
    mitre_name="Brute Force: Password Spraying",
    tactic="Credential Access",
    summary=(
        "An attacker tries one or a few common passwords against many accounts "
        "(or many passwords against one), producing a burst of failed sign-ins."
    ),
    attacker_goal="Find a valid credential without tripping per-account lockout.",
    log_sources=["Entra ID Sign-in logs", "Microsoft Sentinel SigninLogs"],
    audit_operations=["UserLoginFailed", "Sign-in failure (ResultType 50126 / 50053 / 50055)"],
    key_fields=[
        {"field": "ResultType", "check": "50126 invalid credential; 50053 account locked"},
        {"field": "IPAddress / autonomousSystemNumber", "check": "single source hitting many users"},
        {"field": "appDisplayName", "check": "legacy/ROPC clients or unusual app IDs"},
    ],
    what_to_look_for=[
        "Many distinct usernames failing from one IP/ASN in a short window",
        "A low number of attempts per account (spray, not brute-force) to dodge lockout",
        "Failures against legacy auth endpoints (ROPC) that bypass modern controls",
    ],
    false_positives=[
        "A misconfigured client or mobile device replaying a stale password",
        "Post-password-change apps still holding the old secret",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "SigninLogs\n"
            "| where ResultType in ('50126','50053','50055','50076')\n"
            "| summarize failures=count(), users=dcount(UserPrincipalName)\n"
            "    by IPAddress, bin(TimeGenerated, 15m)\n"
            "| where users >= 5 and failures >= 20\n"
            "| order by failures desc",
            "Flags one source failing against many accounts (spray signature).",
        ),
    ],
    response_steps=[
        "Confirm whether any account in the burst later succeeded from the same IP",
        "Block/at-risk the source IP; enforce Smart Lockout thresholds",
        "Ensure legacy authentication (ROPC/basic) is disabled via Conditional Access",
        "Reset any account that both failed here and later signed in successfully",
    ],
    saas_alerts_event="IAM Event - Multiple Auth Failures",
    remediation="Smart Lockout / IP Review",
    references=["https://attack.mitre.org/techniques/T1110/003/"],
)

_DEVICE_CODE = TechniqueReference(
    key="device_code",
    title="Device Code Phishing",
    phase="Initial Access",
    mitre_technique="T1566.002",
    mitre_name="Phishing: Spearphishing Link (device-code variant)",
    tactic="Initial Access / Credential Access",
    summary=(
        "The attacker initiates a device-code flow and sends the victim the code "
        "+ the legitimate Microsoft verification URL. The victim authenticates, "
        "and the attacker collects the resulting token on their own device."
    ),
    attacker_goal="Obtain a valid access/refresh token without stealing the password, bypassing many phishing-resistant checks.",
    log_sources=["Entra ID Sign-in logs (interactive + non-interactive)"],
    audit_operations=["Sign-in with authenticationProtocol = deviceCode"],
    key_fields=[
        {"field": "authenticationProtocol", "check": "'deviceCode' is rare in most tenants"},
        {"field": "IPAddress (init) vs sign-in IP", "check": "code requested and redeemed from different geographies"},
        {"field": "appDisplayName", "check": "public clients like 'Microsoft Office' used from odd locations"},
    ],
    what_to_look_for=[
        "Any deviceCode sign-in where your tenant doesn't legitimately use that flow",
        "A gap between where the code was issued and where the user authenticated",
        "A successful token issuance quickly followed by mailbox/Graph enumeration",
    ],
    false_positives=[
        "Genuine device-code use for CLI tools, IoT/A-V devices, or PowerShell",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "SigninLogs\n"
            "| where AuthenticationProtocol == 'deviceCode'\n"
            "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType\n"
            "| order by TimeGenerated desc",
            "Surfaces all device-code sign-ins; baseline the legitimate ones, alert on the rest.",
        ),
    ],
    response_steps=[
        "Revoke the user's sessions and refresh tokens (this is the key step)",
        "Reset credentials if the account is business-critical",
        "Hunt for what the token was used for next (rules, forwarding, downloads)",
        "Consider a Conditional Access policy blocking the device-code flow where unused",
    ],
    saas_alerts_event="IAM Event - Cross-Device Code Auth",
    remediation="Revoke Active Sessions",
    references=["https://attack.mitre.org/techniques/T1566/002/"],
)

_MFA_PROMPT = TechniqueReference(
    key="mfa_prompt",
    title="MFA Fatigue / Prompt Bombing",
    phase="Initial Access",
    mitre_technique="T1621",
    mitre_name="Multi-Factor Authentication Request Generation",
    tactic="Credential Access",
    summary=(
        "Holding a valid password, the attacker triggers repeated MFA push "
        "prompts hoping the user eventually approves one out of habit or fatigue."
    ),
    attacker_goal="Turn a stolen password into a full sign-in by getting one MFA approval.",
    log_sources=["Entra ID Sign-in logs", "Authentication details"],
    audit_operations=["Sign-in interrupted (50076 / 50079 / 50074)", "Repeated MFA challenges"],
    key_fields=[
        {"field": "ResultType", "check": "50074/50076/50079 repeated for one user"},
        {"field": "authenticationStepResultDetail", "check": "'MFA denied' / 'user did not respond' streaks"},
        {"field": "IPAddress", "check": "prompts driven from an IP the user never signs in from"},
    ],
    what_to_look_for=[
        "Many MFA challenges for one user in minutes, mostly denied/timed-out",
        "A final approval right after a run of denials (the fatigue payoff)",
        "Correct password + failing second factor = password is already compromised",
    ],
    false_positives=[
        "A user repeatedly retrying a flaky push on poor connectivity",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "SigninLogs\n"
            "| where ResultType in ('50074','50076','50079')\n"
            "| summarize prompts=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)\n"
            "| where prompts >= 5\n"
            "| order by prompts desc",
            "Bursts of MFA interrupts per user; pivot to whether one was later approved.",
        ),
    ],
    response_steps=[
        "Treat the password as compromised: reset it and revoke sessions",
        "Move the user to phishing-resistant MFA (FIDO2 / passkey) or number matching",
        "Check whether any prompt in the burst was approved and what followed",
    ],
    saas_alerts_event="IAM Event - Multiple MFA Prompts",
    remediation="Force Passkey / FIDO2",
    references=["https://attack.mitre.org/techniques/T1621/"],
)

_CONSENT = TechniqueReference(
    key="consent_url",
    title="Illicit OAuth Consent Grant",
    phase="Initial Access",
    mitre_technique="T1528",
    mitre_name="Steal Application Access Token",
    tactic="Credential Access / Persistence",
    summary=(
        "The user is lured into consenting to a malicious (or attacker-controlled) "
        "OAuth app that requests broad Graph scopes such as Mail.ReadWrite. The "
        "grant survives password resets."
    ),
    attacker_goal="Gain durable, token-based access to mail/files that a password reset won't revoke.",
    log_sources=["Entra ID Audit logs", "Enterprise Applications"],
    audit_operations=["Consent to application", "Add delegated permission grant", "Add app role assignment to user"],
    key_fields=[
        {"field": "target app", "check": "unfamiliar publisher / newly registered app"},
        {"field": "permissions granted", "check": "Mail.ReadWrite, Files.ReadWrite.All, offline_access"},
        {"field": "consentType", "check": "user consent where admin consent should be required"},
    ],
    what_to_look_for=[
        "User consent to apps requesting high-value mail/file scopes",
        "Newly registered or single-tenant apps receiving broad delegated grants",
        "offline_access requested (refresh token = long-lived access)",
    ],
    false_positives=[
        "Legitimate SaaS onboarding where staff consent to a known vendor app",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "AuditLogs\n"
            "| where OperationName in ('Consent to application','Add delegated permission grant')\n"
            "| extend app = tostring(TargetResources[0].displayName)\n"
            "| project TimeGenerated, InitiatedBy, app, Result, AdditionalDetails\n"
            "| order by TimeGenerated desc",
            "Review every consent event; alert on high-value scopes and unknown apps.",
        ),
    ],
    response_steps=[
        "Revoke the enterprise app's grant and disable the service principal",
        "Require admin consent for future grants; restrict user consent to verified publishers",
        "Audit what the app accessed via its token while the grant was live",
    ],
    saas_alerts_event="Policy Event - OAuth App Consented",
    remediation="Revoke Enterprise App",
    references=["https://attack.mitre.org/techniques/T1528/"],
)

# ---------------------------------------------------------------------------
# Post-breach techniques
# ---------------------------------------------------------------------------

_INBOX_RULE = TechniqueReference(
    key="inbox_rule",
    title="Malicious Inbox / Email Hiding Rule",
    phase="Post-Breach",
    mitre_technique="T1564.008",
    mitre_name="Hide Artifacts: Email Hiding Rules",
    tactic="Defense Evasion",
    summary=(
        "After taking over a mailbox, the attacker creates a rule that auto-reads, "
        "moves, or deletes mail - typically to hide replies to phishing sent from "
        "the account, or security notifications."
    ),
    attacker_goal="Hide their activity from the legitimate mailbox owner and delay detection.",
    log_sources=["Exchange Online (Unified Audit Log)", "Defender for Cloud Apps"],
    audit_operations=["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"],
    key_fields=[
        {"field": "RuleName", "check": "blank, single-character, or generic ('.', 'a', 'rule')"},
        {"field": "actions", "check": "MarkAsRead / MoveToFolder (Deleted Items, RSS Feeds, Archive)"},
        {"field": "ClientIP / client", "check": "created from a non-Outlook client or new IP"},
    ],
    what_to_look_for=[
        "Rules created moments after a sign-in from a new IP/ASN",
        "Rules that move security/finance keywords to Deleted Items or an obscure folder",
        "Blank or single-character rule names (a classic evasion tell)",
    ],
    false_positives=[
        "Power users who genuinely organise mail with move/mark-read rules",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "OfficeActivity\n"
            "| where Operation in ('New-InboxRule','Set-InboxRule')\n"
            "| extend params = tostring(Parameters)\n"
            "| where params has_any ('Deleted Items','RSS','Archive','MarkAsRead','MoveToFolder')\n"
            "| project TimeGenerated, UserId, ClientIP, Operation, params\n"
            "| order by TimeGenerated desc",
            "Inbox rules with hiding-style actions; correlate ClientIP with risky sign-ins.",
        ),
        DetectionQuery(
            "UAL Search (Purview)",
            "Search the Unified Audit Log for Activities = 'New-InboxRule','Set-InboxRule' "
            "and review the ForwardTo / MoveToFolder / MarkAsRead parameters.",
        ),
    ],
    response_steps=[
        "Disable or delete the rule",
        "Revoke the user's sessions and refresh tokens",
        "Check for companion forwarding rules and mailbox delegation",
        "Determine what mail was hidden while the rule was active",
    ],
    saas_alerts_event="Email Event - Suspicious Inbox Rule Created",
    remediation="Disable Rule / Revoke Sessions",
    references=["https://attack.mitre.org/techniques/T1564/008/"],
)

_FORWARDING = TechniqueReference(
    key="mail_forwarding",
    title="External Mail Forwarding Rule",
    phase="Post-Breach",
    mitre_technique="T1114.003",
    mitre_name="Email Collection: Email Forwarding Rule",
    tactic="Collection / Exfiltration",
    summary=(
        "The attacker sets a forwarding rule (inbox rule ForwardTo, or mailbox "
        "ForwardingSmtpAddress) so a copy of incoming mail is silently sent to an "
        "address they control."
    ),
    attacker_goal="Continuously exfiltrate mail even after losing interactive access.",
    log_sources=["Exchange Online (Unified Audit Log)", "Defender for Cloud Apps"],
    audit_operations=["New-InboxRule (ForwardTo/RedirectTo)", "Set-Mailbox (ForwardingSmtpAddress)", "Set-InboxRule"],
    key_fields=[
        {"field": "ForwardingSmtpAddress / ForwardTo", "check": "any EXTERNAL recipient domain"},
        {"field": "DeliverToMailboxAndForward", "check": "false = owner may never see the mail"},
        {"field": "ClientIP", "check": "set from an unusual client/IP"},
    ],
    what_to_look_for=[
        "Any forwarding to a domain outside the org (especially free webmail)",
        "Mailbox-level ForwardingSmtpAddress set outside a change window",
        "Rules that forward then delete, so the owner sees nothing",
    ],
    false_positives=[
        "Sanctioned forwarding for shared mailboxes or during staff departure",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "OfficeActivity\n"
            "| where Operation in ('Set-Mailbox','New-InboxRule','Set-InboxRule')\n"
            "| extend p = tostring(Parameters)\n"
            "| where p has_any ('ForwardingSmtpAddress','ForwardTo','RedirectTo')\n"
            "| project TimeGenerated, UserId, ClientIP, Operation, p\n"
            "| order by TimeGenerated desc",
            "Combine with a check that the forward target domain is external.",
        ),
    ],
    response_steps=[
        "Remove the forwarding address/rule",
        "Block auto-forwarding to external domains at the transport-rule / OWA policy level",
        "Revoke sessions and reset the account",
        "Assess what was exfiltrated while forwarding was active (data-breach scoping)",
    ],
    saas_alerts_event="Email Event - External Forwarding Configured",
    remediation="Remove Forwarding / Block Auto-Forward",
    references=["https://attack.mitre.org/techniques/T1114/003/"],
)

_PASSWORD_CHANGE = TechniqueReference(
    key="password_change",
    title="Account Password Change (Takeover Lock-out)",
    phase="Post-Breach",
    mitre_technique="T1098",
    mitre_name="Account Manipulation",
    tactic="Persistence",
    summary=(
        "The attacker changes the compromised account's password to retain control "
        "and/or lock out the legitimate user."
    ),
    attacker_goal="Cement control of the account and delay the owner's recovery.",
    log_sources=["Entra ID Audit logs"],
    audit_operations=["Change user password", "Change password (self-service)", "Reset user password", "Update user"],
    key_fields=[
        {"field": "InitiatedBy", "check": "self-service change from an unusual IP, or an unexpected admin"},
        {"field": "IPAddress / location", "check": "change from a location the user never uses"},
        {"field": "correlation", "check": "password change right after a risky sign-in"},
    ],
    what_to_look_for=[
        "A self-service password change immediately following a suspicious sign-in",
        "Password changes clustered with MFA-method changes (full takeover pattern)",
        "Admin-initiated resets from an account that isn't the normal helpdesk",
    ],
    false_positives=[
        "Legitimate scheduled password rotation or genuine self-service reset",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "AuditLogs\n"
            "| where OperationName in ('Change user password','Reset user password','Change password (self-service)')\n"
            "| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result\n"
            "| order by TimeGenerated desc",
            "Join to SigninLogs risky sign-ins on UPN within a short window for high fidelity.",
        ),
    ],
    response_steps=[
        "Reset the password again (admin-forced) and revoke all sessions/tokens",
        "Re-verify the owner's identity out-of-band before handing access back",
        "Review MFA methods and app grants added around the same time",
    ],
    saas_alerts_event="IAM Event - Suspicious Password Change",
    remediation="Force Reset / Revoke Tokens",
    references=["https://attack.mitre.org/techniques/T1098/"],
)

_MFA_REGISTRATION = TechniqueReference(
    key="mfa_registration",
    title="Attacker-Registered MFA Method",
    phase="Post-Breach",
    mitre_technique="T1556.006",
    mitre_name="Modify Authentication Process: Multi-Factor Authentication",
    tactic="Persistence",
    summary=(
        "The attacker registers their own MFA method (phone, authenticator, email) "
        "on the compromised account so future sign-ins pass MFA as them."
    ),
    attacker_goal="Establish durable MFA-satisfying persistence that survives a password reset.",
    log_sources=["Entra ID Audit logs (Authentication Methods)"],
    audit_operations=[
        "User registered security info", "Admin registered security info",
        "User registered all required security info", "Add strong authentication method",
    ],
    key_fields=[
        {"field": "authenticationMethod", "check": "new phone/authenticator added from a new device/IP"},
        {"field": "InitiatedBy", "check": "self-service registration during a suspicious session"},
        {"field": "timing", "check": "registration right after takeover, alongside a password change"},
    ],
    what_to_look_for=[
        "A new MFA method registered from an IP/device the user has never used",
        "Security-info registration clustered with a password change or risky sign-in",
        "Multiple methods added in quick succession",
    ],
    false_positives=[
        "Genuine user enrolling a new phone or setting up passkeys",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "AuditLogs\n"
            "| where OperationName has 'registered security info'\n"
            "   or OperationName has 'strong authentication method'\n"
            "| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ResultReason\n"
            "| order by TimeGenerated desc",
            "Correlate with a first-seen device/IP for the user to cut false positives.",
        ),
    ],
    response_steps=[
        "Remove the attacker-registered method; review all registered methods",
        "Revoke sessions/tokens and force re-registration by the verified owner",
        "Check Conditional Access / registration policies for gaps that allowed it",
    ],
    saas_alerts_event="IAM Event - Suspicious Security Info Registered",
    remediation="Remove Method / Review Auth Methods",
    references=["https://attack.mitre.org/techniques/T1556/006/"],
)

_ROLE_ASSIGNMENT = TechniqueReference(
    key="role_assignment",
    title="Privilege Escalation via Directory Role",
    phase="Post-Breach",
    mitre_technique="T1098.003",
    mitre_name="Account Manipulation: Additional Cloud Roles",
    tactic="Privilege Escalation / Persistence",
    summary=(
        "The attacker assigns a privileged Entra directory role to a controlled "
        "account, escalating from a normal user toward tenant control."
    ),
    attacker_goal="Gain admin-level control to disable defences, add persistence, or reach more data.",
    log_sources=["Entra ID Audit logs", "PIM audit"],
    audit_operations=["Add member to role", "Add eligible member to role", "Add member to role in PIM"],
    key_fields=[
        {"field": "role", "check": "Global Admin, Privileged Role Admin, Exchange Admin, Application Admin"},
        {"field": "InitiatedBy", "check": "an account that isn't a normal role administrator"},
        {"field": "target", "check": "a recently created or non-admin account being elevated"},
    ],
    what_to_look_for=[
        "Any assignment of a high-privilege role outside a change window",
        "Role granted by an account that itself was recently compromised",
        "Newly created accounts being added to admin roles",
    ],
    false_positives=[
        "Legitimate admin onboarding or PIM activation by an authorised approver",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "AuditLogs\n"
            "| where OperationName in ('Add member to role','Add eligible member to role')\n"
            "| extend role = tostring(TargetResources[0].displayName)\n"
            "| project TimeGenerated, role, InitiatedBy, TargetResources, Result\n"
            "| order by TimeGenerated desc",
            "Alert on privileged role names; verify the initiator is an authorised admin.",
        ),
    ],
    response_steps=[
        "Remove the role assignment and revoke the elevated account's sessions",
        "Review everything the elevated account did while privileged",
        "Move privileged roles behind PIM with approval + MFA if not already",
    ],
    saas_alerts_event="IAM Event - Privileged Role Assigned",
    remediation="Remove Role / PIM Review",
    references=["https://attack.mitre.org/techniques/T1098/003/"],
)

_ANON_SHARING = TechniqueReference(
    key="anonymous_sharing",
    title="Anonymous / 'Anyone' Sharing Link",
    phase="Post-Breach",
    mitre_technique="T1213.002",
    mitre_name="Data from Information Repositories: SharePoint",
    tactic="Collection / Exfiltration",
    summary=(
        "The attacker creates an anonymous ('Anyone with the link') sharing link on "
        "a SharePoint/OneDrive file so its contents can be pulled without signing in."
    ),
    attacker_goal="Exfiltrate documents through a link that needs no credentials and evades user-based controls.",
    log_sources=["SharePoint/OneDrive (Unified Audit Log)", "Defender for Cloud Apps"],
    audit_operations=["AnonymousLinkCreated", "SharingSet", "AddedToSecureLink", "AnonymousLinkUsed"],
    key_fields=[
        {"field": "link scope", "check": "'Anyone'/anonymous vs. organisation/specific-people"},
        {"field": "target file", "check": "sensitive documents, bulk export files, PST/ZIP"},
        {"field": "AnonymousLinkUsed", "check": "access from external/unknown IPs after creation"},
    ],
    what_to_look_for=[
        "Anonymous links created on sensitive or bulk files",
        "A spike in link creation from one user shortly after a risky sign-in",
        "AnonymousLinkUsed events from unexpected geographies",
    ],
    false_positives=[
        "Legitimate external collaboration where anonymous links are permitted",
    ],
    detections=[
        DetectionQuery(
            "Microsoft Sentinel (KQL)",
            "OfficeActivity\n"
            "| where Operation in ('AnonymousLinkCreated','AnonymousLinkUsed','SharingSet')\n"
            "| project TimeGenerated, UserId, Operation, SourceFileName, TargetUserOrGroupName, ClientIP\n"
            "| order by TimeGenerated desc",
            "Baseline normal sharing; alert on anonymous links to sensitive libraries.",
        ),
    ],
    response_steps=[
        "Revoke the sharing link/permission on the affected item(s)",
        "Tighten tenant/site sharing policy (disable 'Anyone' links where possible)",
        "Scope which files were exposed and whether the link was used externally",
        "Revoke the user's sessions and investigate the initial compromise",
    ],
    saas_alerts_event="Data Event - Anonymous Sharing Link Created",
    remediation="Revoke Link / Restrict Sharing",
    references=["https://attack.mitre.org/techniques/T1213/002/"],
)


REFERENCE_LIBRARY: dict[str, TechniqueReference] = {
    r.key: r for r in [
        _AUTH_FAILURE, _DEVICE_CODE, _MFA_PROMPT, _CONSENT,
        _INBOX_RULE, _FORWARDING, _PASSWORD_CHANGE, _MFA_REGISTRATION,
        _ROLE_ASSIGNMENT, _ANON_SHARING,
    ]
}
