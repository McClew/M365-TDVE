# M365 Telemetry & Detection Validation Engine (TDVE)

A defensive, purple-team utility for MSPs / MSOCs. It executes controlled, deterministic OAuth interactions against a **declared Microsoft 365 test tenant** to generate predictable identity and application audit telemetry, so you can validate that **CDR** correctly ingests, classifies, alerts, and auto-remediates the resulting events.

> **Scope & safety**
>
>  This tool generates *telemetry*, not compromise. Use it only on test tenants you own or are contractually authorised to assess.

## What each module does

| Module (`--module`) | Behaviour | Expected CDR event | Remediation validated |
| --- | --- | --- | --- |
| `auth_failure` | Sends rate-limited ROPC calls with a **deliberately invalid** password to produce `AADSTS50126` failed-sign-in entries. It does **not** guess valid passwords. | IAM Event – Multiple Auth Failures | Smart Lockout / IP Review |
| `device_code` | Initiates the device-authorisation flow (`/devicecode`); optionally polls `/token` to show the pending lifecycle. | IAM Event – Cross-Device Code Auth | Revoke Active Sessions |
| `mfa_prompt` | Issues repeated primary-auth challenges (needs a valid test-account password) to generate MFA-prompt telemetry. | IAM Event – Multiple MFA Prompts | Force Passkey / FIDO2 |
| `consent_url` | **Builds and prints** an `/authorise` URL with extended Graph scopes for you to consent to yourself. Sends nothing to third parties. | Policy Event – OAuth App Consented | Revoke Enterprise App |

## Install

```bash
python -m pip install -r requirements.txt
```

Requires Python 3.10+ and only `requests` + `pyyaml` (NFR-2; runs on Windows, macOS, Linux).

## Configure

```bash
cp config/config.example.yaml config/config.yaml
# edit config/config.yaml - set your TEST tenant, client_id, and test UPNs
```

Then, in `config/config.yaml`:

- Declare the tenant via `tenant.id` (GUID) **or** `tenant.domain`.
- Provide a public-client `client_id` from an app registration in that tenant.

Supply any valid test-account password via the `M365TDVE_TEST_PASSWORD`
environment variable rather than the config file:

```bash
export M365TDVE_TEST_PASSWORD='...'   # PowerShell: $env:M365TDVE_TEST_PASSWORD='...'
```

## Run

Traverse to the project directory and run the single entry-point file:

```bash
# Single module
python m365-tdve.py --config config/config.yaml --module auth_failure

# All modules
python m365-tdve.py --config config/config.yaml --module all

# Override tenant / user at the CLI
python m365-tdve.py --config config/config.yaml \
    --tenant example.onmicrosoft.com --user detection.test@example.onmicrosoft.com \
    --module device_code
```

> The package form (`python -m src.cli ...`) still works and is equivalent;
> `m365-tdve.py` is a thin launcher around it.

Outputs:

- `validation_run.log` - full execution log with HTTP status + Entra error codes.
- `validation_summary.json` - structured per-module summary.
- Console report mapping each module to its expected CDR detection.

## msInvader handoff

`src/handoff/msinvader_config.py` generates an msInvader-style YAML config
skeleton for a subsequent authorised adversary-simulation run. It writes a
template only (secrets left env-driven) and performs no post-exploitation
itself.

## Project layout

```
m365-tdve.py                 Single-file entry point (run this)
config/config.example.yaml   Example config (copy to config.yaml)
src/cli.py                   CLI entry point
src/config_loader.py         Config + safety gate
src/logger.py                Console + file logging
src/auth_client.py           OAuth HTTP client, 429/timeout handling
src/modules/                 Telemetry modules
src/handoff/                 msInvader config generator
src/summary.py               Summary printer + JSON
```
