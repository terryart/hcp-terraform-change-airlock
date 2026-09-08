# Testing and evidence

This project treats tests as evidence for governance properties, not just code coverage.

## Local environment

Validated against:

- Python 3.13
- RailCall Station v1.5.17
- RailCall v2 tree-signed module format

## Unit / adversarial suite

Run:

```bash
python -m unittest discover -s tests -v
```

Current result: **33/33 passing**.

### Manifest and capability boundary

The suite verifies:

- exactly 10 declared commands
- every command has `preview: true`
- every command requires a signed receipt
- every external mutation is `write_requires_approval`
- network egress is only `app.terraform.io`
- subprocess execution is disabled
- filesystem writes are empty
- forbidden high-blast-radius commands are absent
- every declared command maps to a handler function
- the handler does not read environment credentials

### Credential path and redaction

The suite verifies:

- documented RailCall vault shapes resolve correctly
- token loading goes through `vault_get`
- provider error text cannot echo the configured token

### HTTP and failure semantics

The suite verifies:

- 401 is surfaced as credential rejection
- 404 preserves HCP Terraform's not-found/unauthorized ambiguity
- 409 is surfaced as provider-state conflict
- HTTP 202 with an empty body is accepted for queued run actions
- an unreadable successful write response becomes `UNKNOWN`, not success
- write transport failure becomes `UNKNOWN`
- read transport failure remains an ordinary network error
- unlock 503 is surfaced without automatic retry

### Run-creation guards

The suite verifies:

- destroy is rejected
- `plan_and_apply` is refused when workspace auto-apply is enabled
- `plan_and_apply` is refused while the workspace is locked
- `refresh_only` is refused while locked
- `plan_only` remains available while locked
- `save_plan` remains available while locked
- local-execution workspaces are refused by the API-run path

### Run-action guards

The suite verifies:

- apply requires the provider's current `is-confirmable` capability
- apply re-checks workspace lock
- successful apply request reports `queued_not_completed`
- discard requires current `is-discardable`
- cancel requires current `is-cancelable`

### Workspace-action guards

The suite verifies:

- duplicate lock is refused without a POST
- duplicate unlock is refused without a POST
- successful lock returns current provider workspace state

## RailCall bundle verification

The project is signed with the local marketplace publisher key using:

```bash
railcall market module sign .
railcall market module verify .
```

Current signed-bundle verification:

- Ed25519 signature valid
- manifest version 2 tree bundle
- publisher ownership matches the local publisher key
- 10 commands declared
- `.moduleignore` prevents local caches, virtual environments, Git metadata, environment files, logs, and CI metadata from entering the signed payload

**Important:** any change to a signed file invalidates the previous signature. The module is always re-signed after final edits.

## Real Station loader validation

The module has been passed through the local-development install path used by RailCall itself:

```bash
railcall market install --from-path .
```

RailCall Station v1.5.17 reported:

```text
✓ installed + loaded
terryart/hcp-terraform-change-airlock — 10 command(s) registered
```

This proves the current Station loader accepts the signed bundle and registers the declared command surface. It does **not** prove the HCP Terraform API behavior; that is covered by the live sandbox stage below.

## Live HCP Terraform sandbox validation

**Status: completed on 2026-09-08 against a disposable zero-resource workspace.**

The live lab used a dedicated HCP Terraform workspace with no managed resources. The credential was stored through RailCall Vault and was never added to the repository, receipts, or test fixtures.

### Successful live paths

| Path | RailCall result | Provider evidence |
| --- | --- | --- |
| `verify_connection` | `executed`, signed receipt | HCP Terraform HTTP `200` |
| `list_workspaces` | `executed`, signed receipt | workspace reported remote execution, auto-apply off, zero resources |
| `plan_only` create | `executed`, signed receipt | HCP Terraform HTTP `201`; direct read later `planned_and_finished`, `has_changes=false` |
| workspace lock | `executed`, signed receipt | HCP Terraform HTTP `200`; independent read `locked=true` with exact reason |
| workspace unlock | `executed`, signed receipt | HCP Terraform HTTP `200`; independent read `locked=false` |
| `get_run` | `executed`, signed receipt | `planned_and_finished`; confirmable/cancelable/discardable all false |

### Live guard/refusal matrix

| Adversarial provider state / request | Proven result |
| --- | --- |
| auto-apply enabled + `plan_and_apply` | `failed_safely`; guard refused a run path that could apply after the RailCall approval boundary |
| locked workspace + `refresh_only` | `failed_safely`; state-affecting run not queued |
| already-locked workspace + second lock payload | `failed_safely`; existing lock reason preserved; no duplicate lock request sent |
| finished run + apply | `failed_safely`; provider did not advertise the run as confirmable |
| finished run + cancel | `failed_safely`; provider did not advertise the run as cancelable |
| finished run + discard | `failed_safely`; provider did not advertise the run as discardable |
| local-execution workspace + API run creation | `failed_safely`; module required remote or agent execution for the governed API path |

The workspace was restored after adversarial tests to **remote execution, auto-apply off, unlocked, zero resources**.

### Receipt verification

RailCall Station v1.5.17's own `/api/receipts/verify` auditor was run over the HCP Terraform approval/final receipts generated by the live session:

- **32 receipts checked**
- **32 PASS**
- **0 FAIL**
- checks included integrity-hash recomputation, known result status, exact-payload approval binding, explicit approval method, executed-write approval binding where applicable, and Ed25519 verification against the pinned install public key

### Evidence caveats

- A `failed_safely` command receipt reports `external_api_touched=false` even when the module performed a provider **preflight read** before refusing the write. In this project that field is therefore treated as evidence that the external mutation was not executed, not as proof that no provider read occurred.
- During validation, the HCP Terraform workspace-runs collection occasionally returned an empty page while the known run remained directly readable by run ID. The run-ID read was retained as the provider-state proof rather than presenting the collection view as authoritative.
- Live testing intentionally did **not** manufacture destructive infrastructure or force an apply merely to exercise a success path. Apply/cancel/discard were tested live when HCP Terraform advertised them as unavailable, and the module correctly refused them.
- Provider error semantics for HTTP `401`, ambiguous `404`, `409`, unlock `503`, unreadable write responses, and ambiguous post-send transport failures remain **adversarial-unit-tested**, not claimed as live-provider induced failures.

No production organization, valuable cloud credential, destructive Terraform configuration, or managed cloud resource was used for contest validation.

## Evidence discipline

The repository and contest materials will distinguish among:

- **unit-tested** behavior
- **Station-loader validated** behavior
- **live-provider validated** behavior
- **not yet tested** behavior

No result is promoted from one category to another without evidence.
