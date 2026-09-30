# Telemetry trigger modules (FR-2.x)

from .base import ModuleResult, TelemetryModule
from .auth_failure import AuthFailureModule
from .device_code import DeviceCodeModule
from .mfa_prompt import MfaPromptModule
from .consent_url import ConsentUrlModule

MODULE_REGISTRY = {
    "auth_failure": AuthFailureModule,
    "device_code": DeviceCodeModule,
    "mfa_prompt": MfaPromptModule,
    "consent_url": ConsentUrlModule,
}

__all__ = [
    "ModuleResult",
    "TelemetryModule",
    "AuthFailureModule",
    "DeviceCodeModule",
    "MfaPromptModule",
    "ConsentUrlModule",
    "MODULE_REGISTRY",
]
