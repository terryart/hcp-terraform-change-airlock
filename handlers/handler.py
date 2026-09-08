"""HCP Terraform Change Airlock for RailCall.

Governed HCP Terraform run and workspace actions. Credentials are resolved only
through RailCall's vault helper. Every network mutation is expected to be gated
by RailCall preview -> approve -> execute -> signed receipt.

Design constraints:
- no force-cancel, force-execute, force-unlock, destroy, or workspace deletion;
- no automatic write retries;
- standard plan/apply run creation is refused when workspace auto-apply is on;
- writes preflight current provider state and refuse stale / invalid actions;
- transport ambiguity after a write is reported as UNKNOWN, never success.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://app.terraform.io/api/v2"
PROVIDER = "hcp-terraform"
TOKEN_FIELD = "HCP_TERRAFORM_TOKEN"
ALLOWED_RUN_OPERATIONS = {
    "plan_and_apply",
    "plan_only",
    "save_plan",
    "refresh_only",
}

_TOKEN_RE = re.compile(r"(?i)(?:Bearer\s+)?(?:[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]{8,}|[A-Za-z0-9_-]{40,})")
_AUTH_RE = re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+")
_SECRET_FIELD_RE = re.compile(r"(?i)(HCP_TERRAFORM_TOKEN\s*[:=]\s*)[^\s,;]+")


def _redact(value, *secrets):
    text = str(value or "")
    for secret in secrets:
        if isinstance(secret, str) and secret:
            text = text.replace(secret, "[REDACTED]")
    text = _AUTH_RE.sub(r"\1[REDACTED]", text)
    text = _SECRET_FIELD_RE.sub(r"\1[REDACTED]", text)
    return text


def _extract_token(entry):
    if isinstance(entry, str):
        return entry.strip()
    if not isinstance(entry, dict):
        return ""
    fields = entry.get("fields")
    if isinstance(fields, dict):
        value = fields.get(TOKEN_FIELD)
        if isinstance(value, str) and value.strip():
            return value.strip()
    value = entry.get(TOKEN_FIELD)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return ""


def _load_token():
    helpers = globals().get("__rc_helpers__")
    if not isinstance(helpers, dict):
        raise RuntimeError("RailCall module helpers are unavailable; HCP Terraform vault access is not available.")
    vault_get = helpers.get("vault_get")
    if not callable(vault_get):
        raise RuntimeError("RailCall vault_get helper is unavailable. Update RailCall Station before using this module.")
    try:
        entry = vault_get(PROVIDER)
    except Exception:
        raise RuntimeError("RailCall could not read the HCP Terraform vault entry.") from None
    token = _extract_token(entry)
    if not token:
        raise RuntimeError(
            "HCP Terraform credentials are not configured. Add HCP_TERRAFORM_TOKEN "
            "to the RailCall vault entry for provider 'hcp-terraform'."
        )
    return token


def _tls_context():
    return ssl.create_default_context()


def _json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _error_detail(payload, token):
    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            parts = []
            for item in errors[:3]:
                if isinstance(item, dict):
                    title = str(item.get("title") or "").strip()
                    detail = str(item.get("detail") or "").strip()
                    status = str(item.get("status") or "").strip()
                    msg = ": ".join(x for x in (title, detail) if x)
                    if status and msg:
                        msg = f"{status} {msg}"
                    if msg:
                        parts.append(msg)
            if parts:
                return _redact("; ".join(parts), token)
    return ""


def _unknown_write_outcome(detail):
    raise RuntimeError(
        "HCP Terraform write outcome is UNKNOWN because no definitive provider response was received. "
        "Inspect HCP Terraform before approving a retry. " + detail
    ) from None


def _raw_request(method, path, body=None, *, is_write=False):
    token = _load_token()
    url = BASE_URL + path
    data = None if body is None else _json_bytes(body)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
        "User-Agent": "railcall-hcp-terraform-change-airlock/0.1.0",
    }
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30, context=_tls_context()) as response:
            return int(response.getcode()), response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(), exc.headers
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        detail = _redact(getattr(exc, "reason", exc), token).strip() or type(exc).__name__
        if is_write:
            _unknown_write_outcome(f"Transport detail: {detail}")
        raise RuntimeError(f"HCP Terraform network error: {detail}") from None


def _parse_json(body_bytes):
    if not body_bytes:
        return None
    try:
        return json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _api(method, path, body=None, *, expected=(200,), is_write=False, action_name="request"):
    status, body_bytes, headers = _raw_request(method, path, body, is_write=is_write)
    payload = _parse_json(body_bytes)
    token = _load_token()

    if status in expected:
        if body_bytes and payload is None:
            if is_write:
                _unknown_write_outcome(
                    f"Provider returned HTTP {status} for {action_name}, but the response body was unreadable."
                )
            raise RuntimeError(f"HCP Terraform returned an unreadable response for {action_name} (HTTP {status}).")
        return status, payload, headers

    detail = _error_detail(payload, token)
    suffix = f": {detail}" if detail else ""

    if status == 401:
        raise RuntimeError("HCP Terraform rejected the token (HTTP 401). Check the RailCall vault credential.")
    if status == 404:
        raise RuntimeError(
            f"HCP Terraform returned HTTP 404 for {action_name}. The resource may not exist or this token may not be authorized; "
            "HCP Terraform intentionally uses the same response for both."
        )
    if status == 409:
        raise RuntimeError(f"HCP Terraform refused {action_name} because provider state does not permit it (HTTP 409){suffix}")
    if status == 422:
        raise RuntimeError(f"HCP Terraform rejected the {action_name} payload (HTTP 422){suffix}")
    if status == 429:
        retry_after = headers.get("Retry-After") if headers else None
        wait = f" Retry-After: {retry_after}." if retry_after else ""
        raise RuntimeError(f"HCP Terraform rate limit reached (HTTP 429).{wait}")

    # HashiCorp explicitly documents unlock 503 while an intermediate state
    # version is still being finalized. Do not hide the retry behind the
    # original approval: surface it and require a fresh approval later.
    if status == 503 and path.endswith("/actions/unlock"):
        raise RuntimeError(
            "HCP Terraform did not unlock the workspace (HTTP 503): the latest intermediate state version may still be finalizing. "
            "This module does not auto-retry writes; wait briefly, verify state, then approve a new unlock attempt."
        )

    if is_write and status >= 500:
        _unknown_write_outcome(f"Provider returned HTTP {status} for {action_name}{suffix}")
    raise RuntimeError(f"HCP Terraform {action_name} failed with HTTP {status}{suffix}")


def _required_string(inputs, key, label=None):
    value = inputs.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label or key} is required.")
    return value.strip()


def _optional_string(inputs, key, max_len=None):
    value = inputs.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string.")
    value = value.strip()
    if not value:
        return None
    if max_len is not None and len(value) > max_len:
        raise ValueError(f"{key} must be at most {max_len} characters.")
    return value


def _bounded_int(value, default, minimum, maximum, name):
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer.") from None
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return parsed


def _relationship_id(data, name):
    rels = data.get("relationships") if isinstance(data, dict) else None
    rel = rels.get(name) if isinstance(rels, dict) else None
    item = rel.get("data") if isinstance(rel, dict) else None
    if isinstance(item, dict):
        return str(item.get("id") or "")
    return ""


def _workspace_summary(data):
    attrs = data.get("attributes") if isinstance(data, dict) else {}
    attrs = attrs if isinstance(attrs, dict) else {}
    return {
        "workspace_id": str(data.get("id") or ""),
        "name": str(attrs.get("name") or ""),
        "locked": bool(attrs.get("locked")),
        "locked_reason": str(attrs.get("locked-reason") or ""),
        "auto_apply": bool(attrs.get("auto-apply")),
        "execution_mode": str(attrs.get("execution-mode") or ""),
        "terraform_version": str(attrs.get("terraform-version") or ""),
        "resource_count": attrs.get("resource-count"),
        "updated_at": str(attrs.get("updated-at") or ""),
    }


def _run_summary(data):
    attrs = data.get("attributes") if isinstance(data, dict) else {}
    attrs = attrs if isinstance(attrs, dict) else {}
    actions = attrs.get("actions") if isinstance(attrs.get("actions"), dict) else {}
    return {
        "run_id": str(data.get("id") or ""),
        "status": str(attrs.get("status") or ""),
        "operation": str(attrs.get("operation") or ""),
        "message": str(attrs.get("message") or "")[:300],
        "has_changes": attrs.get("has-changes"),
        "created_at": str(attrs.get("created-at") or ""),
        "source": str(attrs.get("source") or ""),
        "workspace_id": _relationship_id(data, "workspace"),
        "plan_id": _relationship_id(data, "plan"),
        "apply_id": _relationship_id(data, "apply"),
        "is_confirmable": bool(actions.get("is-confirmable")),
        "is_discardable": bool(actions.get("is-discardable")),
        "is_cancelable": bool(actions.get("is-cancelable")),
    }


def _get_workspace(workspace_id):
    _, payload, _ = _api("GET", f"/workspaces/{urllib.parse.quote(workspace_id, safe='')}", action_name="get workspace")
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise RuntimeError("HCP Terraform returned no usable workspace object.")
    return data


def _get_run(run_id):
    _, payload, _ = _api("GET", f"/runs/{urllib.parse.quote(run_id, safe='')}", action_name="get run")
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise RuntimeError("HCP Terraform returned no usable run object.")
    return data


def hcp_terraform_verify_connection(inputs, stamp):
    status, payload, _ = _api("GET", "/account/details", action_name="verify connection")
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise RuntimeError("HCP Terraform returned no authenticated account object.")
    attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
    auth_rel = _relationship_id(data, "authenticated-resource")
    auth_data = ((data.get("relationships") or {}).get("authenticated-resource") or {}).get("data") if isinstance(data.get("relationships"), dict) else None
    auth_type = str(auth_data.get("type") or "") if isinstance(auth_data, dict) else ""
    return {
        "ok": True,
        "http_status": status,
        "account_id": str(data.get("id") or ""),
        "username": str(attrs.get("username") or ""),
        "is_service_account": bool(attrs.get("is-service-account")),
        "auth_method": str(attrs.get("auth-method") or ""),
        "authenticated_resource_id": auth_rel,
        "authenticated_resource_type": auth_type,
    }, None


def hcp_terraform_list_workspaces(inputs, stamp):
    organization = _required_string(inputs, "organization")
    page = _bounded_int(inputs.get("page"), 1, 1, 10000, "page")
    page_size = _bounded_int(inputs.get("page_size"), 20, 1, 50, "page_size")
    query = urllib.parse.urlencode({"page[number]": page, "page[size]": page_size})
    path = f"/organizations/{urllib.parse.quote(organization, safe='')}/workspaces?{query}"
    status, payload, _ = _api("GET", path, action_name="list workspaces")
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("HCP Terraform returned no usable workspace list.")
    workspaces = [_workspace_summary(row) for row in rows if isinstance(row, dict)]
    meta = payload.get("meta") if isinstance(payload, dict) and isinstance(payload.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    return {
        "ok": True,
        "http_status": status,
        "organization": organization,
        "returned_count": len(workspaces),
        "current_page": pagination.get("current-page", page),
        "total_count": pagination.get("total-count"),
        "total_pages": pagination.get("total-pages"),
        "workspaces_json": json.dumps(workspaces, separators=(",", ":")),
    }, None


def hcp_terraform_list_runs(inputs, stamp):
    workspace_id = _required_string(inputs, "workspace_id")
    page = _bounded_int(inputs.get("page"), 1, 1, 10000, "page")
    page_size = _bounded_int(inputs.get("page_size"), 20, 1, 30, "page_size")
    params = {"page[number]": page, "page[size]": page_size}
    if bool(inputs.get("include_plan_only", True)):
        params["filter[operation]"] = "plan_only,plan_and_apply,save_plan,refresh_only,destroy,empty_apply,action_only"
    path = f"/workspaces/{urllib.parse.quote(workspace_id, safe='')}/runs?{urllib.parse.urlencode(params)}"
    status, payload, _ = _api("GET", path, action_name="list runs")
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("HCP Terraform returned no usable run list.")
    runs = [_run_summary(row) for row in rows if isinstance(row, dict)]
    return {
        "ok": True,
        "http_status": status,
        "workspace_id": workspace_id,
        "returned_count": len(runs),
        "runs_json": json.dumps(runs, separators=(",", ":")),
    }, None


def hcp_terraform_get_run(inputs, stamp):
    run_id = _required_string(inputs, "run_id")
    data = _get_run(run_id)
    result = _run_summary(data)
    result.update({"ok": True, "http_status": 200})
    return result, None


def hcp_terraform_create_run(inputs, stamp):
    workspace_id = _required_string(inputs, "workspace_id")
    operation = _required_string(inputs, "operation")
    if operation not in ALLOWED_RUN_OPERATIONS:
        raise ValueError(
            "operation must be one of: plan_and_apply, plan_only, save_plan, refresh_only. "
            "Destroy and force-style operations are intentionally not exposed by this module."
        )
    message = _optional_string(inputs, "message", 500) or "Queued through RailCall HCP Terraform Change Airlock"
    configuration_version_id = _optional_string(inputs, "configuration_version_id", 128)

    workspace = _get_workspace(workspace_id)
    ws = _workspace_summary(workspace)

    if ws["execution_mode"] == "local":
        raise RuntimeError(
            "Refusing to queue an API run for a workspace in local execution mode. "
            "Use a remote or agent execution workspace for this governed API path."
        )
    if operation == "plan_and_apply" and ws["auto_apply"]:
        raise RuntimeError(
            "Governance guard: this workspace has auto-apply enabled. An API-created standard run could apply after planning "
            "without a second RailCall approval. Disable HCP Terraform auto-apply or use plan_only/save_plan before retrying."
        )
    if operation in {"plan_and_apply", "refresh_only"} and ws["locked"]:
        raise RuntimeError(
            f"Governance guard: workspace is locked{': ' + ws['locked_reason'] if ws['locked_reason'] else ''}. "
            "This run mode can affect state/resources and is not queued while the workspace is locked."
        )

    attrs = {"message": message}
    if operation == "plan_only":
        attrs["plan-only"] = True
    elif operation == "save_plan":
        attrs["save-plan"] = True
    elif operation == "refresh_only":
        attrs["refresh-only"] = True

    relationships = {"workspace": {"data": {"type": "workspaces", "id": workspace_id}}}
    if configuration_version_id:
        relationships["configuration-version"] = {
            "data": {"type": "configuration-versions", "id": configuration_version_id}
        }

    body = {"data": {"type": "runs", "attributes": attrs, "relationships": relationships}}
    status, payload, _ = _api(
        "POST", "/runs", body, expected=(201,), is_write=True, action_name="create run"
    )
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        _unknown_write_outcome("HTTP 201 was returned but no run object was present.")
    result = _run_summary(data)
    result.update(
        {
            "ok": True,
            "http_status": status,
            "requested_operation": operation,
            "workspace_auto_apply": ws["auto_apply"],
            "workspace_locked": ws["locked"],
            "governance_guard": "auto_apply_checked",
        }
    )
    return result, None


def _queued_run_action(inputs, action):
    run_id = _required_string(inputs, "run_id")
    comment = _optional_string(inputs, "comment", 500)
    run = _get_run(run_id)
    summary = _run_summary(run)
    capability = {
        "apply": "is_confirmable",
        "discard": "is_discardable",
        "cancel": "is_cancelable",
    }[action]
    if not summary[capability]:
        raise RuntimeError(
            f"Governance guard: run {run_id} is status '{summary['status']}' and HCP Terraform does not advertise it as {action}-able. "
            "No write was attempted."
        )

    if action == "apply":
        workspace_id = summary["workspace_id"]
        if workspace_id:
            workspace = _workspace_summary(_get_workspace(workspace_id))
            if workspace["locked"]:
                raise RuntimeError(
                    "Governance guard: the run's workspace is currently locked. No apply request was sent."
                )
    body = {"comment": comment} if comment else None
    status, _, _ = _api(
        "POST",
        f"/runs/{urllib.parse.quote(run_id, safe='')}/actions/{action}",
        body,
        expected=(202,),
        is_write=True,
        action_name=f"{action} run",
    )
    return {
        "ok": True,
        "http_status": status,
        "run_id": run_id,
        "action": action,
        "queued": True,
        "preflight_status": summary["status"],
        "provider_confirmation": "queued_not_completed",
    }, None


def hcp_terraform_apply_run(inputs, stamp):
    return _queued_run_action(inputs, "apply")


def hcp_terraform_discard_run(inputs, stamp):
    return _queued_run_action(inputs, "discard")


def hcp_terraform_cancel_run(inputs, stamp):
    return _queued_run_action(inputs, "cancel")


def hcp_terraform_lock_workspace(inputs, stamp):
    workspace_id = _required_string(inputs, "workspace_id")
    reason = _optional_string(inputs, "reason", 500) or "Locked through RailCall HCP Terraform Change Airlock"
    current = _workspace_summary(_get_workspace(workspace_id))
    if current["locked"]:
        raise RuntimeError(
            f"Governance guard: workspace is already locked{': ' + current['locked_reason'] if current['locked_reason'] else ''}. "
            "No duplicate lock request was sent."
        )
    body = {"reason": reason}
    status, payload, _ = _api(
        "POST",
        f"/workspaces/{urllib.parse.quote(workspace_id, safe='')}/actions/lock",
        body,
        expected=(200,),
        is_write=True,
        action_name="lock workspace",
    )
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        _unknown_write_outcome("HTTP 200 was returned for lock, but no workspace object was present.")
    result = _workspace_summary(data)
    result.update({"ok": True, "http_status": status, "action": "lock", "reason": reason})
    return result, None


def hcp_terraform_unlock_workspace(inputs, stamp):
    workspace_id = _required_string(inputs, "workspace_id")
    current = _workspace_summary(_get_workspace(workspace_id))
    if not current["locked"]:
        raise RuntimeError("Governance guard: workspace is already unlocked. No duplicate unlock request was sent.")
    status, payload, _ = _api(
        "POST",
        f"/workspaces/{urllib.parse.quote(workspace_id, safe='')}/actions/unlock",
        None,
        expected=(200,),
        is_write=True,
        action_name="unlock workspace",
    )
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        _unknown_write_outcome("HTTP 200 was returned for unlock, but no workspace object was present.")
    result = _workspace_summary(data)
    result.update({"ok": True, "http_status": status, "action": "unlock"})
    return result, None
