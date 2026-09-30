# Base class and structured result type for telemetry modules

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass
class ModuleResult:
    """Structured JSON-serialisable summary of a module execution."""
    module: str
    expected_saas_alerts_event: str
    target_remediation: str
    started_at: str
    duration_seconds: float
    target_user: str | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class TelemetryModule:
    """Base class: each module emits one deterministic class of telemetry.

    Subclasses declare their expected CDR mapping and implement run().
    """

    key: str = "base"
    expected_event: str = ""
    remediation: str = ""

    def __init__(self, config, client, logger):
        self.config = config
        self.client = client
        self.log = logger
        self.settings = (config.modules or {}).get(self.key, {}) or {}

    def _new_result(self, target_user: str | None = None) -> ModuleResult:
        return ModuleResult(
            module=self.key,
            expected_saas_alerts_event=self.expected_event,
            target_remediation=self.remediation,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            duration_seconds=0.0,
            target_user=target_user,
        )

    def run(self) -> list[ModuleResult]:  # pragma: no cover - interface
        raise NotImplementedError
