# HCP Terraform Change Airlock

A governance-first HCP Terraform integration for RailCall.

**The premise:** infrastructure automation should be fast, but infrastructure *mutation* should remain reviewable. This module lets an AI agent inspect HCP Terraform, prepare bounded run actions, and operate the normal run/workspace lifecycle while RailCall preserves the human authorization boundary:

**stage → preview → approve → execute → signed receipt**

The module uses the real HCP Terraform v2 API. It does not mock writes, read credentials from environment variables, retry ambiguous mutations, or expose force-style shortcuts that bypass normal provider safety.

> Contest build: RailCall Developer Challenge Round 2 (`contest:round2`)

## Why this module exists

A generic Terraform API wrapper is not enough for governed automation.

There is a subtle but important example: HCP Terraform workspace **auto-apply also applies to API-created runs**. A naive integration can therefore receive one human approval to create a run, let planning finish later, and then allow HCP Terraform to apply infrastructure without another RailCall approval.

**HCP Terraform Change Airlock refuses that path.** `hcp_terraform.create_run` will not create a normal `plan_and_apply` run when workspace auto-apply is enabled. The operator must disable auto-apply or choose a non-applying run mode first.

That is the design philosophy throughout this module: preserve the provider's real state machine, then make the human approval boundary explicit at the points where state can change.

## Command surface

| Command | Mode | Risk | Purpose |
|---|---|---:|---|
| `hcp_terraform.verify_connection` | read | medium | Verify the vault token and identify the authenticated resource. |
| `hcp_terraform.list_workspaces` | read | medium | Inspect workspace lock, auto-apply, execution mode, Terraform version, and resource count. |
| `hcp_terraform.list_runs` | read | medium | Inspect a bounded page of workspace runs and their current action capabilities. |
| `hcp_terraform.get_run` | read | medium | Inspect one run, its state, operation, relationships, and advertised actions. |
| `hcp_terraform.create_run` | **write_requires_approval** | high | Queue a bounded non-destroy run after workspace preflight. |
| `hcp_terraform.apply_run` | **write_requires_approval** | high | Re-read a run, require `is-confirmable`, re-check workspace lock, then queue apply. |
| `hcp_terraform.discard_run` | **write_requires_approval** | medium | Re-read a run and queue discard only when provider state allows it. |
| `hcp_terraform.cancel_run` | **write_requires_approval** | high | Queue the normal cancellation path only when provider state allows it. |
| `hcp_terraform.lock_workspace` | **write_requires_approval** | medium | Refuse duplicate lock and lock with an explicit reason. |
| `hcp_terraform.unlock_workspace` | **write_requires_approval** | medium | Refuse duplicate unlock and use only the normal unlock path. |

Every command declares `preview: true` and `receipt_required: true`.

## Deliberately not exposed

The v0.1 contest surface does **not** expose:

- destroy runs
- force-cancel
- force-execute
- force-unlock
- workspace deletion

Those operations are not missing by accident. They either have unusually high blast radius or explicitly bypass normal provider workflow/safety behavior. The contest build chooses a coherent, defensible control surface instead of maximizing command count.

## Governance guards

### 1. Auto-apply guard

`create_run(operation="plan_and_apply")` preflights the workspace and refuses if `auto-apply` is enabled.

This prevents one RailCall approval from silently becoming a later infrastructure apply.

### 2. Provider-state preflight

Before a mutation, the module re-reads the relevant provider object:

- apply requires HCP Terraform to advertise the run as `is-confirmable`
- discard requires `is-discardable`
- cancel requires `is-cancelable`
- apply additionally re-checks the workspace lock
- lock/unlock refuse no-op duplicates

The module does not assume that state observed earlier is still current.

### 3. No invented success

HCP Terraform queues apply/discard/cancel with HTTP `202`. The module reports:

`provider_confirmation = queued_not_completed`

It never turns “accepted for processing” into “completed successfully.”

### 4. Ambiguous write outcomes remain ambiguous

A network timeout after a write request creates an uncomfortable state: the request may have reached the provider even though no definitive response reached the caller.

The module **does not retry** and **does not report failure or success**. It raises an explicit `UNKNOWN` outcome and tells the operator to inspect HCP Terraform before approving a fresh attempt.

### 5. HCP Terraform's intentional 404 ambiguity is preserved

HashiCorp intentionally uses HTTP `404` both when a resource does not exist and when the caller is not authorized to know whether it exists. The module preserves that ambiguity instead of converting it into a misleading “not found.”

### 6. Unlock 503 is not hidden by retry

HCP Terraform documents a temporary `503` on workspace unlock while an intermediate state version is being finalized.

The module surfaces that condition and requires the operator to wait, verify state, and approve a fresh unlock later. It does not silently spend the old approval on a retry.

### 7. Tight capability boundary

The signed module manifest declares:

- network: `app.terraform.io` only
- subprocess: `false`
- filesystem writes: none
- one vault provider: `hcp-terraform`
- one required secret: `HCP_TERRAFORM_TOKEN`

The handler does not read environment variables or credential files.

## Run modes

`hcp_terraform.create_run` exposes four bounded run modes:

- `plan_and_apply`
- `plan_only`
- `save_plan`
- `refresh_only`

`plan_only` and `save_plan` may still be queued while a workspace is locked because they do not apply state. `plan_and_apply` and `refresh_only` are refused while locked.

Workspaces in HCP Terraform `local` execution mode are refused by the API-run path; use a remote or agent execution workspace instead.

## Setup

### 1. Install RailCall Station

Use the current RailCall installer and confirm Station is healthy.

### 2. Create an HCP Terraform API token

Use a **user or team token** with only the permissions your workflow actually requires. Organization tokens cannot perform several run lifecycle actions used by this module.

### 3. Store the token in RailCall Vault

Create the RailCall integration provider:

`hcp-terraform`

with the field:

`HCP_TERRAFORM_TOKEN`

Do not put the token in `.env`, source files, command arguments, GitHub Actions variables for this module, or README examples.

### 4. Install the signed module locally

```bash
railcall market install --from-path /path/to/hcp-terraform-change-airlock
```

The command verifies the Ed25519 bundle first, copies it into Station, reloads modules, and reports whether the real Station loader accepted or rejected it.

## Recommended first run

1. `hcp_terraform.verify_connection`
2. `hcp_terraform.list_workspaces`
3. choose a dedicated sandbox workspace with **auto-apply off**
4. `hcp_terraform.create_run` with `plan_only`
5. `hcp_terraform.get_run`
6. inspect the signed RailCall receipt

Only move into apply/cancel/lock lifecycle testing in a workspace where the blast radius is intentionally zero or trivial.

## Testing

The current local suite contains adversarial tests for the controls above, not only happy-path serialization.

```bash
python -m unittest discover -s tests -v
```

Current local status: **33/33 tests passing**.

The signed v2 module bundle also passes:

```bash
railcall market module verify .
```

and has been accepted by the actual current RailCall Station loader through:

```bash
railcall market install --from-path .
```

See [`TESTING.md`](TESTING.md) for the complete evidence matrix and live-sandbox validation status.

### Live validation snapshot — 2026-09-08

The module has now been exercised through **RailCall Station v1.5.17** against a disposable, zero-resource HCP Terraform workspace. The workspace was kept remote-execution, auto-apply off, and unlocked except when a guard test intentionally changed one of those conditions.

Proven live:

- `verify_connection`, `list_workspaces`, and `get_run` reached HCP Terraform and produced signed RailCall receipts.
- A RailCall-approved `plan_only` run was accepted by HCP Terraform with HTTP `201`; an independent provider read later reported `planned_and_finished` with `has_changes = false`.
- Enabling workspace auto-apply caused a `plan_and_apply` request to end as `failed_safely` before a run write was attempted.
- Locking and unlocking the workspace through RailCall both returned HTTP `200`, and independent HCP Terraform reads matched the receipt state.
- `refresh_only` was refused while the workspace was locked; a duplicate lock was also refused without another lock POST.
- The finished plan-only run advertised `is_confirmable = false`, `is_cancelable = false`, and `is_discardable = false`; RailCall refused apply, cancel, and discard accordingly.
- Switching the disposable workspace to local execution mode caused API run creation to be refused; the workspace was then restored to remote mode.
- **32/32 HCP-related approval/final receipts** from the live session passed RailCall's own receipt verifier, including integrity recomputation, exact-payload approval binding, and Ed25519 verification against the pinned install public key.

No infrastructure resources were created or applied during this validation.

## Security model

See [`SECURITY.md`](SECURITY.md).

The short version: this module reduces the chance that an AI or automation silently mutates HCP Terraform; it does **not** replace HCP Terraform RBAC, workspace permissions, policy checks, Sentinel/OPA controls, provider-side audit logs, or human judgment.

## Source layout

```text
.
├── module.json
├── module.sig
├── handlers/
│   └── handler.py
├── tests/
│   └── test_handler.py
├── README.md
├── SECURITY.md
├── TESTING.md
└── .moduleignore
```

## Status

- [x] 10-command lifecycle implemented
- [x] vault-only auth path
- [x] auto-apply governance guard
- [x] provider-state mutation preflights
- [x] ambiguous-write handling
- [x] 33/33 adversarial unit tests
- [x] RailCall v2 tree signature valid
- [x] current Station loader accepts and registers all 10 commands
- [x] live HCP Terraform sandbox validation
- [x] public GitHub CI run
- [ ] RailCall Marketplace moderation/publish
- [ ] contest submission

The unchecked items stay unchecked until they are actually proven.
