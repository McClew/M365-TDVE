# Telemetry trigger modules (FR-2.x)

from .base import ModuleResult, TelemetryModule
from .auth_failure import AuthFailureModule
from .device_code import DeviceCodeModule
from .mfa_prompt import MfaPromptModule
from .consent_url import ConsentUrlModule
from .inbox_rule import InboxRuleModule
from .mail_forwarding import MailForwardingModule
from .password_change import PasswordChangeModule
from .mfa_registration import MfaRegistrationModule
from .role_assignment import RoleAssignmentModule
from .anonymous_sharing import AnonymousSharingModule

MODULE_REGISTRY = {
    "auth_failure": AuthFailureModule,
    "device_code": DeviceCodeModule,
    "mfa_prompt": MfaPromptModule,
    "consent_url": ConsentUrlModule,
    "inbox_rule": InboxRuleModule,
    "mail_forwarding": MailForwardingModule,
    "password_change": PasswordChangeModule,
    "mfa_registration": MfaRegistrationModule,
    "role_assignment": RoleAssignmentModule,
    "anonymous_sharing": AnonymousSharingModule,
}

__all__ = [
    "ModuleResult",
    "TelemetryModule",
    "AuthFailureModule",
    "DeviceCodeModule",
    "MfaPromptModule",
    "ConsentUrlModule",
    "InboxRuleModule",
    "MailForwardingModule",
    "PasswordChangeModule",
    "MfaRegistrationModule",
    "RoleAssignmentModule",
    "AnonymousSharingModule",
    "MODULE_REGISTRY",
]
