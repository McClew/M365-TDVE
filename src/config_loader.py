# Configuration loading, validation and the safety gate

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# Env var override for the (optional) test-account password so it need not be written to the config file
_PASSWORD_ENV = "M365TDVE_TEST_PASSWORD"

class ConfigError(Exception):
    """Raised when configuration is missing, or invalid."""

@dataclass
class TargetUser:
    upn: str
    password: str = ""

@dataclass
class TrainingConfig:
    """Settings for the SOC training / detection-reference layer."""
    # Output directory for the generated attack reference cards + scenarios.
    cards_dir: str = "training_cards"

@dataclass
class AuthConfig:
    """How the authenticated (post-breach) modules acquire a delegated token.

    ``ropc`` (default) uses the non-interactive password grant - silent and
    per-user, but it CANNOT satisfy MFA (fails with AADSTS50076 on protected
    accounts). ``device_code`` runs one interactive sign-in (complete MFA in a
    browser); the issued token is cached and shared across every module in the
    run.
    """
    delegated_flow: str = "ropc"   # ropc | device_code
    scope: str = "https://graph.microsoft.com/.default offline_access"
    device_code_timeout: int = 300

@dataclass
class EngineConfig:
    tenant: str # GUID or domain, as declared
    client_id: str
    redirect_uri: str
    users: list[TargetUser]
    modules: dict[str, Any]
    auth: AuthConfig = field(default_factory=AuthConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)
    log_file: str = "validation_run.log"
    summary_json: str = "validation_summary.json"
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def authority(self) -> str:
        """OAuth authority base URL for the declared tenant."""
        return f"https://login.microsoftonline.com/{self.tenant}"

def _load_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")
    
    text = path.read_text(encoding="utf-8")

    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise ConfigError("pyyaml is required to load YAML config files.")
        
        data = yaml.safe_load(text)

    elif path.suffix.lower() == ".json":
        data = json.loads(text)

    else:
        raise ConfigError(f"Unsupported config format: {path.suffix}")
    
    if not isinstance(data, dict):
        raise ConfigError("Config root must be a mapping/object.")
    
    return data

def _validate_tenant(tenant_block: dict[str, Any]) -> str:
    tenant_id = (tenant_block.get("id") or "").strip()
    domain = (tenant_block.get("domain") or "").strip()

    if tenant_id:
        if not _GUID_RE.match(tenant_id):
            raise ConfigError(f"tenant.id is not a valid GUID: {tenant_id!r}")
        return tenant_id
    
    if domain:
        if not _DOMAIN_RE.match(domain):
            raise ConfigError(f"tenant.domain is not a valid domain: {domain!r}")
        return domain
    
    raise ConfigError(
        "You must declare the target test tenant via tenant.id (GUID) or tenant.domain."
    )


def load_config(path: str | Path, cli_overrides: dict[str, Any] | None = None) -> EngineConfig: 
    """Load, merge CLI overrides, and validate."""

    data = _load_file(Path(path))
    cli_overrides = cli_overrides or {}

    # Apply CLI overrides onto the loaded structure
    tenant_block = dict(data.get("tenant") or {})
    if cli_overrides.get("tenant"):
        val = cli_overrides["tenant"].strip()

        # Route the override to the correct field based on its shape
        if _GUID_RE.match(val):
            tenant_block = {"id": val, "domain": ""}
        else:
            tenant_block = {"id": "", "domain": val}

    tenant = _validate_tenant(tenant_block)

    # Client
    client_block = data.get("client") or {}
    client_id = (cli_overrides.get("client_id") or client_block.get("client_id") or "").strip()
    
    if not client_id:
        raise ConfigError("client.client_id is required (no default).")
    
    redirect_uri = (client_block.get("redirect_uri") or "http://localhost:8400/callback").strip()

    # Targets
    users: list[TargetUser] = []
    env_password = os.environ.get(_PASSWORD_ENV, "")
    for entry in (data.get("targets") or {}).get("users") or []:
        upn = (entry.get("upn") or "").strip()
        if not upn:
            continue
        password = (entry.get("password") or "").strip() or env_password
        users.append(TargetUser(upn=upn, password=password))

    # A single --user override narrows the target set to that UPN
    if cli_overrides.get("user"):
        wanted = cli_overrides["user"].strip().lower()
        matched = [u for u in users if u.upn.lower() == wanted]
        if not matched:
            # Allow an ad-hoc user not present in the file, but with no password
            matched = [TargetUser(upn=cli_overrides["user"].strip(),
                                  password=env_password)]
        users = matched

    if not users:
        raise ConfigError("No target users declared (targets.users is empty).")

    output_block = data.get("output") or {}

    # Delegated-auth settings for the post-breach modules. A CLI override wins
    # over the file, which wins over the ROPC default.
    a = data.get("auth") or {}
    auth = AuthConfig()
    flow = (cli_overrides.get("delegated_auth")
            or a.get("delegated_flow") or auth.delegated_flow).strip().lower()
    if flow not in ("ropc", "device_code"):
        raise ConfigError(
            f"auth.delegated_flow must be 'ropc' or 'device_code', got {flow!r}"
        )
    auth.delegated_flow = flow
    if a.get("scope"):
        auth.scope = str(a["scope"]).strip()
    if a.get("device_code_timeout"):
        auth.device_code_timeout = int(a["device_code_timeout"])

    # Training / detection-reference settings.
    t = data.get("training") or {}
    training = TrainingConfig(
        cards_dir=(t.get("cards_dir") or "training_cards").strip(),
    )

    return EngineConfig(
        tenant=tenant,
        client_id=client_id,
        redirect_uri=redirect_uri,
        users=users,
        modules=data.get("modules") or {},
        auth=auth,
        training=training,
        log_file=output_block.get("log_file") or "validation_run.log",
        summary_json=output_block.get("summary_json") or "validation_summary.json",
        raw=data,
    )
