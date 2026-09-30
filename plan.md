# Software Requirements Specification (SRS) & Development Task List

**Project Name:** M365 Telemetry & Detection Validation Engine

**Document Version:** 1.0.0

**Target Platform:** Python 3.10+ | Microsoft Entra ID | SaaS Alerts (Kaseya) Integration

---

## 1. System Overview & Objectives

The **M365 Telemetry & Detection Validation Engine** is a specialized defensive utility designed for Managed Service Providers (MSPs) and Managed Security Operations Centers (MSOCs). Its primary objective is to execute controlled, deterministic API interactions against a designated Microsoft 365 test tenant to generate predictable identity and SaaS application audit telemetry.

This telemetry allows security engineers to validate that downstream Cloud Detection and Response (CDR) platforms-specifically **SaaS Alerts**-properly ingest, classify, alert, and auto-remediate security events in accordance with defined MSP SLAs and response playbooks.

---

## 2. System Architecture & High-Level Design

```
+-----------------------------------------------------------------------+
|                       Validation Engine CLI                           |
+-----------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
+-----------------------------------+   +-----------------------------------+
|     Identity Event Generator      |   |    Application Event Generator    |
| (Entra ID / OAuth REST API Layer) |   | (MS Graph / Post-Exploitation)    |
+-----------------------------------+   +-----------------------------------+
         |                                                   |
         +-------------------------+-------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                    Microsoft 365 Unified Audit Log                    |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                   SaaS Alerts Ingestion & RESPOND                     |
+-----------------------------------------------------------------------+

```

---

## 3. Functional Requirements

### 3.1 Authentication & Configuration Module

* **FR-1.1:** The engine MUST accept configuration parameters via both command-line arguments (CLI) and a structured configuration file (`config.json` or `config.yaml`).
* **FR-1.2:** The system MUST support tenant identification using either Microsoft Entra Tenant ID (GUID) or Primary Domain Name (`*.onmicrosoft.com`).
* **FR-1.3:** The engine MUST utilize standard OAuth 2.0 endpoints (`login.microsoftonline.com`) without requiring proprietary third-party software dependencies.

### 3.2 Telemetry Trigger Modules

* **FR-2.1 (Auth Failure Telemetry):** The system MUST include a module capable of sending controlled, rate-limited authentication calls via Resource Owner Password Credentials (ROPC) to produce `50126` (invalid password) Entra sign-in log entries for threshold testing in SaaS Alerts.
* **FR-2.2 (Cross-Device Flow Telemetry):** The system MUST include a module to initiate Device Code authorisation requests to validate cross-device authentication logging.
* **FR-2.3 (Consent Telemetry):** The system MUST include a module to generate OAuth 2.0 authorisation links containing extended scopes (`Mail.ReadWrite`, `Files.ReadWrite.All`) to test application consent logging.
* **FR-2.4 (MFA Prompt Verification):** The system MUST support triggering repeated primary authentication challenges to verify MFA notification timeout and denial event handling.

### 3.3 Post-Exploitation Handoff & Orchestration

* **FR-3.1:** The engine MUST provide a standardized handoff configuration interface to pass generated refresh tokens or credentials to secondary validation tools (e.g., `msInvader`).
* **FR-3.2:** The system MUST log all outbound HTTP responses, status codes, and Entra ID error codes locally to an execution log (`validation_run.log`) for audit cross-referencing.

---

## 4. Non-Functional Requirements

* **NFR-1 (Security & Safety):** The system MUST operate exclusively against explicitly declared test tenant endpoints. Hardcoded credentials or production tenant defaults are strictly prohibited.
* **NFR-2 (Portability):** The software MUST run on Linux, macOS, and Windows operating systems with minimal dependencies (standard Python standard library + `requests`).
* **NFR-3 (Auditability):** Every executed test module MUST output structured JSON summary statistics indicating execution time, target user account, HTTP status, and expected SaaS Alerts event type.

---

## 5. Software Development Task List

> **Implementation status (2026-09-29):** Phases 1–3 complete and covered by an
> offline test suite (10 passing). Phase 4 items that require a live tenant and
> SaaS Alerts console access remain open. See the mapping to source files in
> [`README.md`](README.md).

### Phase 1: Environment Setup & Core Architecture

* [x] **Task 1.1:** Initialize project repository structure (`/src`, `/tests`, `/config`). - `src/`, `src/modules/`, `src/handoff/`, `tests/`, `config/`. _(No `/docs` dir; documentation lives in `README.md`.)_
* [x] **Task 1.2:** Create `requirements.txt` defining core dependencies (`requests>=2.28.0`, `pyyaml>=6.0`). - [`requirements.txt`](requirements.txt).
* [x] **Task 1.3:** Implement CLI argument parser (`argparse`) accepting `--tenant`, `--user`, `--module`, and `--config` options. - [`src/cli.py`](src/cli.py) (plus `--confirm-authorised`, `--client-id`, `--authorised-by`, `--verbose`).
* [x] **Task 1.4:** Build centralized logging module (`logger.py`) supporting console output and file-based execution logs. - [`src/logger.py`](src/logger.py).

### Phase 2: Identity & Authentication Module Development

* [x] **Task 2.1:** Develop `AuthenticationFailure` module to send formatted ROPC requests and capture Entra ID error codes (`50126`, `50053`). - [`src/modules/auth_failure.py`](src/modules/auth_failure.py). Uses a deliberately invalid password to generate failure telemetry; aborts on unexpected success.
* [x] **Task 2.2:** Develop `DeviceCodeAuth` module to handle initial POST to `/devicecode` and implement polling loop logic against `/token`. - [`src/modules/device_code.py`](src/modules/device_code.py).
* [x] **Task 2.3:** Develop `MFAPromptVerification` module with configurable interval delays to test authentication challenge queueing. - [`src/modules/mfa_prompt.py`](src/modules/mfa_prompt.py).
* [x] **Task 2.4:** Develop `ConsentUrlBuilder` helper to construct valid OAuth 2.0 authorisation URLs with custom Graph API scope parameters. - [`src/modules/consent_url.py`](src/modules/consent_url.py). Builds/prints the URL only; transmits nothing.

### Phase 3: Integration & Handoff Orchestration

* [x] **Task 3.1:** Create `msInvader` configuration generator to auto-populate post-exploitation playbooks with acquired test tokens. - [`src/handoff/msinvader_config.py`](src/handoff/msinvader_config.py). Writes a config template with env-driven secret placeholders.
* [x] **Task 3.2:** Implement error handling for network timeouts, rate limiting (HTTP `429 Too Many Requests`), and invalid tenant IDs. - 429/timeout handling in [`src/auth_client.py`](src/auth_client.py); tenant/GUID validation in [`src/config_loader.py`](src/config_loader.py).
* [x] **Task 3.3:** Build execution summary printer displaying expected SaaS Alerts event mappings upon completion of each module. - [`src/summary.py`](src/summary.py) (console report + `validation_summary.json`).

### Phase 4: Validation & Documentation

* [ ] **Task 4.1:** Perform dry-run testing against M365 E5 / Developer test tenant. _(Open - requires live test-tenant credentials. Offline test suite in [`tests/`](tests/) passes.)_
* [ ] **Task 4.2:** Validate event correlation inside the SaaS Alerts dashboard (`IAM Events`, `Policy Events`). _(Open - requires SaaS Alerts console access.)_
* [ ] **Task 4.3:** Verify SaaS Alerts **RESPOND** playbook triggers (auto-session revocation and account lock). _(Open - requires SaaS Alerts console access.)_
* [x] **Task 4.4:** Finalize user documentation and workshop execution playbook. - [`README.md`](README.md) (setup, per-module behaviour, run examples, validation checklist).

---

## 6. Traceability Matrix (Module to SaaS Alerts Detection)

| Module Function | Target Entra / Graph Endpoint | Expected SaaS Alerts Event Category | Target Remediation Action |
| --- | --- | --- | --- |
| `emulate_password_spray()` | `/oauth2/v2.0/token` (ROPC) | `IAM Event - Multiple Auth Failures` | Smart Lockout / IP Review |
| `emulate_device_code_phish()` | `/oauth2/v2.0/devicecode` | `IAM Event - Cross-Device Code Auth` | Revoke Active Sessions |
| `emulate_mfa_fatigue_loop()` | `/oauth2/v2.0/token` | `IAM Event - Multiple MFA Prompts` | Force Passkey / FIDO2 |
| `generate_illicit_consent_url()` | `/oauth2/v2.0/authorise` | `Policy Event - OAuth App Consented` | Revoke Enterprise App |