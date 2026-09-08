# Security model

HCP Terraform Change Airlock is designed to make infrastructure mutations reviewable through RailCall. It is a safety boundary around an API client, not a replacement for HCP Terraform's own authorization and policy controls.

## Security objectives

The module is designed to preserve these properties:

1. **Vault-only credentials.** The HCP Terraform token is resolved only through RailCall's `vault_get` helper.
2. **Tight egress.** The manifest permits network access only to `app.terraform.io`.
3. **No subprocesses or filesystem mutation.** The module does not shell out to Terraform, Git, curl, or any local executable and declares no filesystem-write capability.
4. **Human approval for every external mutation.** All six write commands use `write_requires_approval`, preview, and signed receipts.
5. **Provider-state preflight.** Mutations are refused when the current HCP Terraform object does not advertise or satisfy the required state.
6. **No automatic mutation retries.** An old human approval is never silently reused after a transport failure.
7. **No false completion claims.** HTTP 202 means queued, not completed.
8. **No force-style escape hatches.** Destroy, force-cancel, force-execute, force-unlock, and workspace deletion are absent from v0.1.

## Trust boundaries

### RailCall

RailCall is responsible for:

- module signature verification
- publisher trust decisions
- sandboxing declared capabilities
- credential-vault resolution
- preview / approval gating
- signed receipt creation

The module assumes RailCall provides these primitives correctly. A compromise of RailCall's local approval secret, vault, module loader, or sandbox is outside this module's ability to contain.

### HCP Terraform

HCP Terraform remains authoritative for:

- token permissions and organization/workspace RBAC
- workspace locks
- run state and action capability flags
- policy checks
- state management
- provider-side audit history
- Terraform execution and cloud-provider effects

The module does not attempt to bypass HCP Terraform permissions or reinterpret provider refusal as success.

### Human approver

The human approval boundary is meaningful only if the approver reviews the staged command and inputs. Signed receipts prove what RailCall authorized/executed; they do not prove that an operator made a wise infrastructure decision.

## Auto-apply hazard

HCP Terraform can auto-apply API-created runs when a workspace has auto-apply enabled. That creates a delayed-effect hazard for an airlock: approving creation can implicitly authorize a later apply.

For that reason, `hcp_terraform.create_run(operation="plan_and_apply")` refuses workspaces with auto-apply enabled.

This guard is intentionally stricter than the raw provider API.

## Write ambiguity

A timeout after sending a mutation is not safely classifiable as success or failure. The provider may have received the request.

For write transport failures or unreadable successful write responses, the module reports an explicit `UNKNOWN` outcome and instructs the operator to inspect HCP Terraform before approving any retry.

No mutation is automatically retried.

## Provider error semantics

The module intentionally preserves important HCP Terraform API semantics:

- **401**: invalid or unavailable credential
- **404**: resource may not exist *or* caller may not be authorized; existence is not inferred
- **409**: provider state does not allow the requested action
- **422**: provider rejected the submitted payload
- **429**: rate-limited; Retry-After is surfaced when available
- **5xx after write**: treated as potentially ambiguous rather than a safe retry signal
- **unlock 503**: surfaced as the documented state-finalization condition; no hidden retry

## Secrets

The handler redacts the configured token if it appears in an exception or provider error body and sanitizes authorization-header-shaped text.

Never:

- commit a Terraform token
- store it in `.env` for this module
- paste it into issue reports or contest submissions
- include it in screenshots or demo recordings
- pass it as a command input

Use RailCall Vault provider `hcp-terraform`, field `HCP_TERRAFORM_TOKEN`.

## Recommended token scope

Use the least-privileged **user or team token** that supports the commands you need. Several run lifecycle endpoints do not permit organization tokens.

For contest/live validation, use a dedicated sandbox organization/workspace with no valuable infrastructure and auto-apply disabled.

## Deliberately excluded operations

The v0.1 module excludes several raw HCP Terraform capabilities:

- destroy runs
- force-cancel
- force-execute
- force-unlock
- workspace deletion

The absence of these commands is a control, not a feature gap for the contest build.

## Reporting a security issue

Do not include HCP Terraform tokens, RailCall approval credentials, or private workspace data in a public report. Provide a minimal reproducer with secrets removed and state whether the issue occurs before or after provider confirmation.
