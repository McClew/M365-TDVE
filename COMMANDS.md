# TDVE Command Cheat Sheet

Copy-paste commands for driving `m365-tdve.py`. Run everything from the project
root. Examples show **PowerShell** first (your default shell), then the bash
equivalent where it differs.

> Reminder: there is no dry-run / allowlist gate yet. `--module all` (the
> default) and `--chain` run the **post-breach executors** against every account
> in `targets.users`. Keep that list to disposable test accounts. See the README
> safety note.

---

## 0. One-time setup

```powershell
python -m pip install -r requirements.txt
Copy-Item config/config.example.yaml config/config.yaml   # then edit it
$env:M365TDVE_TEST_PASSWORD = '...'                        # test-account password
```

```bash
# bash
cp config/config.example.yaml config/config.yaml
export M365TDVE_TEST_PASSWORD='...'
```

---

## 1. Reference / training (no tenant contact)

These never touch the tenant — safe to run anywhere.

```powershell
python m365-tdve.py --list-techniques
python m365-tdve.py --list-scenarios
python m365-tdve.py --emit-cards
python m365-tdve.py --emit-cards --cards-dir ./training_cards
```

---

## 2. Single initial-access module (telemetry only)

Each line is independent — copy the one you need.

```powershell
python m365-tdve.py --module auth_failure
python m365-tdve.py --module device_code
python m365-tdve.py --module mfa_prompt
python m365-tdve.py --module consent_url
```

Scope to one user / tenant on the fly:

```powershell
python m365-tdve.py --module device_code --tenant example.onmicrosoft.com --user detection.test@example.onmicrosoft.com
```

---

## 3. Single post-breach module (mutates the test tenant)

Benign + reversible, but real Graph writes. Run one at a time while validating.

```powershell
python m365-tdve.py --module inbox_rule
python m365-tdve.py --module mail_forwarding
python m365-tdve.py --module password_change
python m365-tdve.py --module mfa_registration
python m365-tdve.py --module role_assignment
python m365-tdve.py --module anonymous_sharing
```

Post-breach modules need a delegated token. If ROPC is blocked by MFA, switch flow:

```powershell
python m365-tdve.py --module inbox_rule --delegated-auth device_code
python m365-tdve.py --module inbox_rule --delegated-auth auth_code   # interactive browser
```

---

## 4. Custom sequences (`--sequence`)

Ordered, comma-separated module keys. Unregistered keys are skipped.

```powershell
# Sign-in noise only
python m365-tdve.py --sequence auth_failure,mfa_prompt

# Spray -> fatigue -> persistence
python m365-tdve.py --sequence auth_failure,mfa_prompt,inbox_rule,mail_forwarding

# Space steps out for realistic, spread telemetry (seconds between each)
python m365-tdve.py --sequence auth_failure,mfa_prompt,inbox_rule --step-delay 30
```

---

## 5. Named attack chains (`--chain`)

Runs the scenario's modules in documented order, prints a timeline, and writes
`simulation_timeline.json`.

```powershell
# Business Email Compromise: auth_failure -> mfa_prompt -> inbox_rule -> mail_forwarding -> anonymous_sharing
python m365-tdve.py --chain bec_takeover

# Illicit consent + persistence: device_code -> consent_url -> mfa_registration -> mail_forwarding
python m365-tdve.py --chain consent_persistence

# Privilege escalation: mfa_prompt -> password_change -> role_assignment -> consent_url
python m365-tdve.py --chain privilege_escalation

# Any chain, spread out
python m365-tdve.py --chain bec_takeover --step-delay 30
```

---

## 6. Run everything

```powershell
# DEFAULT = all modules, including post-breach executors, against every target
python m365-tdve.py
python m365-tdve.py --module all
```

---

## 7. Handy flags (mix into any run above)

```powershell
--config config/config.yaml   # explicit config path (default already this)
--tenant <guid|domain>        # override tenant
--user <upn>                  # restrict to one test UPN
--client-id <app-id>          # override public client app ID
--delegated-auth ropc|device_code|auth_code
--step-delay <seconds>        # pace --sequence / --chain
--verbose                     # debug console output
--version
```

Precedence when several are given: `--chain` > `--sequence` > `--module`.

---

## Outputs

| File | What |
| --- | --- |
| `validation_run.log` | full execution log (HTTP status + Entra error codes) |
| `validation_summary.json` | per-module structured summary |
| `simulation_timeline.json` | timeline from a `--sequence` / `--chain` run |
| `training_cards/` | reference cards + `scenarios/` (from `--emit-cards`) |

## Keys quick reference

**Modules:** `auth_failure` · `device_code` · `mfa_prompt` · `consent_url` ·
`inbox_rule` · `mail_forwarding` · `password_change` · `mfa_registration` ·
`role_assignment` · `anonymous_sharing`

**Chains:** `bec_takeover` · `consent_persistence` · `privilege_escalation`
