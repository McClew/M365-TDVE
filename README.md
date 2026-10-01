# M365 Telemetry & Detection Validation Engine (TDVE)

A defensive, purple-team utility for MSPs / MSOCs. It executes controlled, deterministic OAuth and Microsoft Graph interactions against a **declared Microsoft 365 test tenant** to generate predictable identity and application audit telemetry, so you can validate that **CDR** correctly ingests, classifies, alerts, and auto-remediates the resulting events.

> **Scope & safety**
>
> Use this tool only on test tenants you own or are contractually authorised to
> assess, and only against the test accounts you declare in config.
>
> The **initial-access** modules generate failed/interrupted sign-in *telemetry*
> and never guess valid passwords. The **post-breach** modules go further: they
> perform the real (but benign, reversible) Graph write action behind each
> technique - creating a clearly-named inbox rule, a marker-gated forwarding
> rule, a throwaway MFA method, a low-impact role assignment, etc. - and then
> clean up after themselves. They are *benign by construction* (synthetic subject
> markers so no live mail is touched, reserved test phone ranges, low-impact
> roles), but they do mutate the tenant, so treat the declared target list as
> live blast radius.
>
> There is **no dry-run / `--live` gate and no target allowlist yet** - a module
> acts on every account in `targets.users` the moment you invoke it. Keep that
> list limited to disposable test accounts.

## What each module does

### Initial-access modules

These generate sign-in / consent telemetry only and never perform a compromise.

| Module (`--module`) | Behaviour | Expected CDR event | Remediation validated |
| --- | --- | --- | --- |
| `auth_failure` | Sends rate-limited ROPC calls with a **deliberately invalid** password to produce `AADSTS50126` failed-sign-in entries. It does **not** guess valid passwords. | IAM Event – Multiple Auth Failures | Smart Lockout / IP Review |
| `device_code` | Initiates the device-authorisation flow (`/devicecode`); optionally polls `/token` to show the pending lifecycle. | IAM Event – Cross-Device Code Auth | Revoke Active Sessions |
| `mfa_prompt` | Issues repeated primary-auth challenges (needs a valid test-account password) to generate MFA-prompt telemetry. | IAM Event – Multiple MFA Prompts | Force Passkey / FIDO2 |
| `consent_url` | **Builds and prints** an `/authorise` URL with extended Graph scopes for you to consent to yourself. Sends nothing to third parties. | Policy Event – OAuth App Consented | Revoke Enterprise App |

### Post-breach modules

These authenticate as a declared test account (delegated ROPC token) and perform
the **real, but benign and reversible**, Graph write action behind each
technique, then clean up (`cleanup: true` by default). They mutate the test
tenant - see the safety note above. Tunables live in each `modules.<key>` config
block; privileged ones read an `admin_upn` (which must also be a declared target,
since that is where the ROPC password lives).

| Module (`--module`) | Benign action it performs | Expected audit op | Remediation validated |
| --- | --- | --- | --- |
| `inbox_rule` | Creates a marker-gated inbox rule (`markAsRead` on a synthetic subject), then deletes it. | `New-InboxRule` | Disable rule / revoke sessions |
| `mail_forwarding` | Creates a marker-gated rule that forwards to a sink address you control, then deletes it. No live mail is forwarded. | `New-InboxRule` (ForwardTo) | Remove forwarding / block auto-forward |
| `password_change` | Self-service password change (`/me/changePassword`) on a disposable account. **Really rotates the password** - update the stored credential afterwards. | Change user password | Force reset / revoke tokens |
| `mfa_registration` | Adds a reserved-range test phone method, then removes it. `reset_existing: true` (throwaway accounts only) also wipes pre-existing methods first. Needs an Authentication Administrator `admin_upn`. | User/Admin registered security info | Remove method / review auth methods |
| `role_assignment` | Assigns a low-impact directory role (default *Directory Readers*) resolved by name, then removes it. Needs a Privileged Role Administrator `admin_upn`. | Add member to role | Remove role / PIM review |
| `anonymous_sharing` | Creates an anonymous ("Anyone with the link") link to a sandbox `drive_id`/`item_id` you set, then revokes it. | `AnonymousLinkCreated` | Revoke link / restrict sharing |

## Running a multi-module simulation

You can run several modules **in sequence** to exercise a whole attack chain in
one go - chaining the initial-access and post-breach modules to test the
end-to-end simulation (e.g. spray → MFA fatigue → inbox rule → forwarding).

```bash
# Explicit ordered list of module keys
python m365-tdve.py --sequence auth_failure,mfa_prompt,inbox_rule

# Run a named attack-chain scenario (see --list-scenarios)
python m365-tdve.py --chain bec_takeover

# Space the steps out (seconds between each) for more realistic, spread telemetry
python m365-tdve.py --chain bec_takeover --step-delay 30
```

Precedence when more than one is given: `--chain` > `--sequence` > `--module`.

The runner executes whatever is registered in `MODULE_REGISTRY`. A module key
that isn't registered yet (e.g. a post-exploitation module you haven't built) is
reported as **"not built yet" and skipped**, so the same chain stays runnable as
you fill it in - build a module, register it, and it slots straight into the
chain. A step that raises is logged and the chain continues.

A sequence/chain run prints a **simulation timeline** (what ran, when, and the
outcome) and writes it to `simulation_timeline.json`. The named scenarios come
from the reference library (`--list-scenarios`), so the chain you *run* lines up
with the chain the SOC-training cards *document*.

## SOC training & detection reference

Beyond running the modules, the engine ships an **attack reference library** so
on-call SOC and support engineers have a frame of reference for what these
attacks look like - covering both the initial-access and post-breach techniques
(inbox rules, mail forwarding, password changes, MFA-method registration,
illicit consent, privilege escalation, anonymous sharing).

This library is **pure reference material - it describes attacks and their audit
signals, and it never contacts the tenant**. It is independent of the executable
modules: the post-breach *modules* above perform the benign, reversible version
of a technique against your test tenant, while the reference *card* for the same
technique documents what to hunt for and how to respond. Each card maps to its
module by key (e.g. `inbox_rule.md` ↔ the `inbox_rule` module).

Each technique card covers: what the attack is, its MITRE ATT&CK mapping, the
exact Unified Audit Log / Entra audit **operations and fields** it produces, how
to tell it from benign activity, ready-to-tune **KQL hunting queries**, and a
**response runbook** that ties back to the remediation you're validating.

```bash
# List the technique catalogue and the documented attack-chain scenarios
python m365-tdve.py --list-techniques
python m365-tdve.py --list-scenarios

# Generate the full reference: one markdown card per technique, an index,
# and per-scenario timelines (+ a machine-readable timelines.json)
python m365-tdve.py --emit-cards
python m365-tdve.py --emit-cards --cards-dir ./training_cards   # custom output dir
```

Output under the cards directory (default `training_cards/`, or `training.cards_dir`):

- `README.md` - index of all techniques, split into Initial Access / Post-Breach
- `<technique>.md` - one card per technique (e.g. `inbox_rule.md`)
- `scenarios/<name>.md` - attack-chain walkthroughs with a step-by-step timeline
- `scenarios/timelines.json` - the same chains as structured data

The **scenarios** stitch techniques into realistic narratives (e.g. spray →
MFA fatigue → inbox rule → forwarding → anonymous sharing) so trainees can see
how alerts correlate over time - ideal for tabletop exercises: reveal one step
at a time and have engineers name the detection and the response.

When you run the telemetry modules, the execution summary now also prints the
MITRE technique and the matching reference card for each module.

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
   added by default. The sign-in modules request
   `https://graph.microsoft.com/.default`, which only resolves to permissions
   configured on the app, so at least one must be there.
2. **For the post-breach modules**, add and **grant admin consent** for the
   delegated permissions each one needs (they also authenticate with
   `.default`, so the scope must already be consented on the app - it is not
   requested interactively). Only add the permissions for the modules you
   actually intend to run:

   | Module | Delegated permission(s) | Also requires |
   | --- | --- | --- |
   | `inbox_rule`, `mail_forwarding` | `MailboxSettings.ReadWrite` | - |
   | `password_change` | `Directory.AccessAsUser.All` | disposable account |
   | `mfa_registration` | `UserAuthenticationMethod.ReadWrite.All` | `admin_upn` holds *Authentication Administrator* |
   | `role_assignment` | `RoleManagement.ReadWrite.Directory` | `admin_upn` holds *Privileged Role Administrator* |
   | `anonymous_sharing` | `Files.ReadWrite.All` (or `Sites.ReadWrite.All`) | tenant/site policy permits anonymous links |

   Confirm the exact scope against the current
   [Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
   for each call before relying on it.
3. The `consent_url` module is the exception: it exists so that *you* consent to
   extended scopes (e.g. `Mail.ReadWrite`, `Files.ReadWrite.All`) yourself,
   generating the *Policy Event – OAuth App Consented* telemetry. If you have
   already granted admin consent for those scopes (e.g. because you run
   `mail_forwarding`), consenting again may not produce a fresh event - keep a
   separate app registration for the consent drill if you need both.

### 4. Prepare the test accounts

- Use **cloud-only** test users. ROPC doesn't work for federated or
  passwordless-only accounts.
- **Security Defaults / Conditional Access:** these can block ROPC outright.
  That's fine for `auth_failure`, which only needs failed sign-ins. For
  `mfa_prompt`, the account must be MFA-registered and in a state where it gets
  an MFA challenge (`AADSTS50076` / `AADSTS50079`) rather than a hard block.
  If needed, scope a Conditional Access exclusion to the TDVE app and the test
  users only.
- **Post-breach modules** acquire a delegated token via ROPC, so every acting
  account - each target and any `admin_upn` - needs a valid password on file
  (`targets.users[].password` or `M365TDVE_TEST_PASSWORD`) and must be able to
  complete ROPC without an MFA interrupt. The privileged `admin_upn` accounts
  must also hold the role noted in step 3. Use disposable accounts, especially
  for `password_change` (which rotates the password for real).
- Don't run this against real users' accounts.

### 5. Reference configuration

| Setting | Value |
| --- | --- |
| Supported account types | Single tenant |
| Platform | Mobile and desktop applications |
| Redirect URI | `http://localhost:8400/callback` |
| Allow public client flows | Yes |
| Client secret / certificate | None |
| API permissions | Microsoft Graph (Delegated): `User.Read`, **plus** the per-module write scopes in step 3 for any post-breach modules you run |
| Admin consent | Granted for the post-breach write scopes you use; **not** granted for the `consent_url` drill scopes |

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

# All modules (see the warning below - this now includes the post-breach executors)
python m365-tdve.py --config config/config.yaml --module all

# Override tenant / user at the CLI
python m365-tdve.py --config config/config.yaml \
    --tenant example.onmicrosoft.com --user detection.test@example.onmicrosoft.com \
    --module device_code
```

> **`all` is the default, and it now runs every registered module - including the
> post-breach executors** (`password_change`, `role_assignment`, …) against every
> account in `targets.users`. A bare `python m365-tdve.py` is therefore no longer
> a telemetry-only run. Until a dry-run/`--live` gate exists, pass an explicit
> `--module <key>` (or a scoped `--sequence` / `--chain`) when you only want the
> sign-in modules, and keep `targets.users` limited to disposable test accounts.

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
src/runner.py                Multi-module sequence runner (--sequence / --chain)
src/training/                Attack reference library, cards, and scenarios
src/handoff/                 msInvader config generator
src/summary.py               Summary printer + JSON
```
