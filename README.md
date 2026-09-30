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

## Prerequisite: Entra app registration

Every OAuth call the engine makes (ROPC, device code, and the consent URL)
sends a `client_id`, and there is no built-in default. You need to register a
**public client** app in the test tenant before you run anything. Using an app
you own also means the telemetry is tied to an app you control.

### 1. Register the app

1. Sign in to the [Microsoft Entra admin centre](https://entra.microsoft.com)
   as an admin of the **test** tenant.
2. Go to **Identity → App registrations → New registration**.
3. Set:
   - **Name:** `M365 TDVE` (or anything that's easy to spot in the audit logs)
   - **Supported account types:** *Accounts in this organisational directory only (Single tenant)*
   - **Redirect URI:** leave blank for now (you'll add it in step 2)
4. Click **Register**. From the **Overview** page, copy the
   **Application (client) ID** and the **Directory (tenant) ID**.

### 2. Configure authentication

On the app's **Authentication** blade:

1. **Add a platform → Mobile and desktop applications**. Leave the suggested
   redirect URI checkboxes unticked.
   Type `http://localhost:8400/callback` into the custom redirect URI box
   underneath them (placeholder text: `e.g. myapp://auth`), then click
   **Configure**. This must match `client.redirect_uri` in your config
   exactly.
2. Open the **Settings** tab (next to the redirect URI
   configuration tab) and switch **Allow public client flows** on.

   Without this, ROPC (`auth_failure`, `mfa_prompt`) and device code
   (`device_code`) fail with `AADSTS7000218`.
3. Click **Save**.

Don't create a client secret or certificate. The engine is a public client.

### 3. Configure API permissions

On the **API permissions** blade:

1. Make sure **Microsoft Graph → Delegated → `User.Read`** is present. It's
   added by default. The `device_code` and `mfa_prompt` modules request
   `https://graph.microsoft.com/.default`, which only resolves to permissions
   configured on the app, so at least one must be there.
2. **Don't** add or grant admin consent for `Mail.ReadWrite` or
   `Files.ReadWrite.All`. The `consent_url` module exists so that *you*
   consent to these scopes yourself, which generates the
   *Policy Event – OAuth App Consented* telemetry. If consent has already been
   granted, you may not get that event.

### 4. Prepare the test accounts

- Use **cloud-only** test users. ROPC doesn't work for federated or
  passwordless-only accounts.
- **Security Defaults / Conditional Access:** these can block ROPC outright.
  That's fine for `auth_failure`, which only needs failed sign-ins. For
  `mfa_prompt`, the account must be MFA-registered and in a state where it gets
  an MFA challenge (`AADSTS50076` / `AADSTS50079`) rather than a hard block.
  If needed, scope a Conditional Access exclusion to the TDVE app and the test
  users only.
- Don't run this against real users' accounts.

### 5. Reference configuration

| Setting | Value |
| --- | --- |
| Supported account types | Single tenant |
| Platform | Mobile and desktop applications |
| Redirect URI | `http://localhost:8400/callback` |
| Allow public client flows | Yes |
| Client secret / certificate | None |
| API permissions | Microsoft Graph (Delegated): `User.Read` |
| Admin consent | Not granted for the extended scopes |

Put the IDs from step 1 into `config/config.yaml`:

```yaml
tenant:
  id: "<Directory (tenant) ID>"
client:
  client_id: "<Application (client) ID>"
  redirect_uri: "http://localhost:8400/callback"
```

You can also pass `--client-id` on the command line to override the config.

## Configure

```bash
cp config/config.example.yaml config/config.yaml
# edit config/config.yaml - set your TEST tenant, client_id, and test UPNs
```

Then, in `config/config.yaml`:

- Declare the tenant via `tenant.id` (GUID) **or** `tenant.domain`.
- Provide the `client_id` from the app registration you created in
  [Prerequisite: Entra app registration](#prerequisite-entra-app-registration).

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
