import importlib.util
import json
import pathlib
import unittest
from unittest import mock
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hcp_handler", ROOT / "handlers" / "handler.py")
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)


def workspace(*, locked=False, auto_apply=False, execution_mode="remote", reason=""):
    return {
        "id": "ws-test",
        "type": "workspaces",
        "attributes": {
            "name": "contest-sandbox",
            "locked": locked,
            "locked-reason": reason,
            "auto-apply": auto_apply,
            "execution-mode": execution_mode,
            "terraform-version": "1.9.8",
            "resource-count": 0,
            "updated-at": "2026-09-08T00:00:00Z",
        },
    }


def run(*, status="planned", confirmable=False, discardable=False, cancelable=False):
    return {
        "id": "run-test",
        "type": "runs",
        "attributes": {
            "status": status,
            "operation": "plan_and_apply",
            "message": "contest",
            "has-changes": True,
            "created-at": "2026-09-08T00:00:00Z",
            "source": "tfe-api",
            "actions": {
                "is-confirmable": confirmable,
                "is-discardable": discardable,
                "is-cancelable": cancelable,
            },
        },
        "relationships": {
            "workspace": {"data": {"id": "ws-test", "type": "workspaces"}},
            "plan": {"data": {"id": "plan-test", "type": "plans"}},
            "apply": {"data": None},
        },
    }


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "module.json").read_text(encoding="utf-8"))

    def test_exactly_ten_commands(self):
        self.assertEqual(len(self.manifest["commands"]), 10)

    def test_every_command_requires_receipt_and_preview(self):
        for command in self.manifest["commands"]:
            self.assertTrue(command["receipt_required"], command["id"])
            self.assertTrue(command["preview"], command["id"])

    def test_every_external_mutation_requires_approval(self):
        writes = [c for c in self.manifest["commands"] if c["id"].split(".", 1)[1] in {
            "create_run", "apply_run", "discard_run", "cancel_run", "lock_workspace", "unlock_workspace"
        }]
        self.assertEqual(len(writes), 6)
        for command in writes:
            self.assertEqual(command["mode"], "write_requires_approval")

    def test_egress_is_tight(self):
        self.assertEqual(self.manifest["requires"]["network"], ["app.terraform.io"])
        self.assertEqual(self.manifest["allowed_destinations"], [
            {"provider": "hcp-terraform", "hosts": ["app.terraform.io"]}
        ])
        self.assertFalse(self.manifest["requires"]["subprocess"])
        self.assertEqual(self.manifest["requires"]["filesystem_writes"], [])

    def test_forbidden_high_blast_radius_commands_absent(self):
        joined = " ".join(c["id"] for c in self.manifest["commands"])
        for forbidden in ("destroy", "force_cancel", "force_execute", "force_unlock", "delete_workspace"):
            self.assertNotIn(forbidden, joined)

    def test_command_functions_exist(self):
        for command in self.manifest["commands"]:
            fn = command["id"].replace(".", "_").replace("-", "_")
            self.assertTrue(hasattr(h, fn), fn)

    def test_handler_does_not_read_environment_credentials(self):
        text = (ROOT / "handlers" / "handler.py").read_text(encoding="utf-8")
        self.assertNotIn("os.environ", text)
        self.assertNotIn("getenv(", text)


class VaultTests(unittest.TestCase):
    def test_extract_token_documented_shapes(self):
        self.assertEqual(h._extract_token(" abc "), "abc")
        self.assertEqual(h._extract_token({"fields": {h.TOKEN_FIELD: " tok "}}), "tok")
        self.assertEqual(h._extract_token({h.TOKEN_FIELD: " tok2 "}), "tok2")
        self.assertEqual(h._extract_token({}), "")

    def test_load_token_only_uses_vault(self):
        old = getattr(h, "__rc_helpers__", None)
        h.__rc_helpers__ = {"vault_get": lambda provider: {"fields": {h.TOKEN_FIELD: "vault-token"}}}
        try:
            self.assertEqual(h._load_token(), "vault-token")
        finally:
            if old is None:
                delattr(h, "__rc_helpers__")
            else:
                h.__rc_helpers__ = old


class ErrorSemanticsTests(unittest.TestCase):
    def api_with(self, status, body=b"", headers=None, *, is_write=False, expected=(200,), path="/x"):
        with mock.patch.object(h, "_raw_request", return_value=(status, body, headers or {})), \
             mock.patch.object(h, "_load_token", return_value="super-secret-token"):
            return h._api("POST" if is_write else "GET", path, expected=expected, is_write=is_write, action_name="test")

    def test_401_is_auth_error(self):
        with self.assertRaisesRegex(RuntimeError, "rejected the token"):
            self.api_with(401)

    def test_404_preserves_not_found_vs_unauthorized_ambiguity(self):
        with self.assertRaisesRegex(RuntimeError, "may not exist or this token may not be authorized"):
            self.api_with(404)

    def test_409_is_provider_state_conflict(self):
        with self.assertRaisesRegex(RuntimeError, "provider state does not permit"):
            self.api_with(409, b'{"errors":[{"detail":"not confirmable"}]}')

    def test_secret_is_redacted_from_provider_error(self):
        body = b'{"errors":[{"detail":"bad credential super-secret-token"}]}'
        try:
            self.api_with(422, body)
        except RuntimeError as exc:
            self.assertNotIn("super-secret-token", str(exc))
            self.assertIn("[REDACTED]", str(exc))
        else:
            self.fail("expected RuntimeError")

    def test_202_empty_action_response_is_valid(self):
        status, payload, _ = self.api_with(202, b"", is_write=True, expected=(202,))
        self.assertEqual(status, 202)
        self.assertIsNone(payload)

    def test_unreadable_success_write_is_unknown_not_success(self):
        with self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
            self.api_with(201, b"not-json", is_write=True, expected=(201,))

    def test_unlock_503_is_explicit_and_not_auto_retried(self):
        with self.assertRaisesRegex(RuntimeError, "does not auto-retry writes"):
            self.api_with(503, b"", is_write=True, expected=(200,), path="/workspaces/ws/actions/unlock")

    def test_transport_failure_on_write_is_unknown(self):
        old = getattr(h, "__rc_helpers__", None)
        h.__rc_helpers__ = {"vault_get": lambda provider: {"fields": {h.TOKEN_FIELD: "vault-token"}}}
        try:
            with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
                with self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
                    h._raw_request("POST", "/runs", {}, is_write=True)
        finally:
            if old is None:
                delattr(h, "__rc_helpers__")
            else:
                h.__rc_helpers__ = old

    def test_transport_failure_on_read_is_not_unknown(self):
        old = getattr(h, "__rc_helpers__", None)
        h.__rc_helpers__ = {"vault_get": lambda provider: {"fields": {h.TOKEN_FIELD: "vault-token"}}}
        try:
            with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
                with self.assertRaisesRegex(RuntimeError, "network error"):
                    h._raw_request("GET", "/account/details", is_write=False)
        finally:
            if old is None:
                delattr(h, "__rc_helpers__")
            else:
                h.__rc_helpers__ = old


class CreateRunGuardsTests(unittest.TestCase):
    def test_destroy_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "intentionally not exposed"):
            h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "destroy"}, None)

    def test_plan_and_apply_refuses_auto_apply_workspace_without_post(self):
        with mock.patch.object(h, "_get_workspace", return_value=workspace(auto_apply=True)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "auto-apply enabled"):
                h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "plan_and_apply"}, None)
            api.assert_not_called()

    def test_plan_and_apply_refuses_locked_workspace(self):
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=True, reason="maintenance")), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "workspace is locked"):
                h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "plan_and_apply"}, None)
            api.assert_not_called()

    def test_refresh_only_refuses_locked_workspace(self):
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=True)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "workspace is locked"):
                h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "refresh_only"}, None)
            api.assert_not_called()

    def test_plan_only_is_allowed_while_locked(self):
        created = run(status="pending")
        created["attributes"]["operation"] = "plan_only"
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=True)), \
             mock.patch.object(h, "_api", return_value=(201, {"data": created}, {})) as api:
            result, _ = h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "plan_only"}, None)
            self.assertTrue(result["ok"])
            body = api.call_args.args[2]
            self.assertIs(body["data"]["attributes"]["plan-only"], True)
            self.assertNotIn("is-destroy", body["data"]["attributes"])

    def test_save_plan_is_allowed_while_locked(self):
        created = run(status="pending")
        created["attributes"]["operation"] = "save_plan"
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=True)), \
             mock.patch.object(h, "_api", return_value=(201, {"data": created}, {})) as api:
            h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "save_plan"}, None)
            body = api.call_args.args[2]
            self.assertIs(body["data"]["attributes"]["save-plan"], True)

    def test_local_execution_workspace_is_refused(self):
        with mock.patch.object(h, "_get_workspace", return_value=workspace(execution_mode="local")), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "local execution mode"):
                h.hcp_terraform_create_run({"workspace_id": "ws-test", "operation": "plan_only"}, None)
            api.assert_not_called()


class RunActionGuardTests(unittest.TestCase):
    def test_apply_refuses_nonconfirmable_run(self):
        with mock.patch.object(h, "_get_run", return_value=run(status="planning")), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "does not advertise it as apply-able"):
                h.hcp_terraform_apply_run({"run_id": "run-test"}, None)
            api.assert_not_called()

    def test_apply_refuses_locked_workspace(self):
        with mock.patch.object(h, "_get_run", return_value=run(status="planned", confirmable=True)), \
             mock.patch.object(h, "_get_workspace", return_value=workspace(locked=True)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "workspace is currently locked"):
                h.hcp_terraform_apply_run({"run_id": "run-test"}, None)
            api.assert_not_called()

    def test_apply_reports_queued_not_completed(self):
        with mock.patch.object(h, "_get_run", return_value=run(status="planned", confirmable=True)), \
             mock.patch.object(h, "_get_workspace", return_value=workspace(locked=False)), \
             mock.patch.object(h, "_api", return_value=(202, None, {})):
            result, _ = h.hcp_terraform_apply_run({"run_id": "run-test", "comment": "approved"}, None)
            self.assertTrue(result["queued"])
            self.assertEqual(result["provider_confirmation"], "queued_not_completed")

    def test_discard_requires_provider_capability(self):
        with mock.patch.object(h, "_get_run", return_value=run(status="planning", discardable=False)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "discard-able"):
                h.hcp_terraform_discard_run({"run_id": "run-test"}, None)
            api.assert_not_called()

    def test_cancel_requires_provider_capability(self):
        with mock.patch.object(h, "_get_run", return_value=run(status="planned", cancelable=False)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "cancel-able"):
                h.hcp_terraform_cancel_run({"run_id": "run-test"}, None)
            api.assert_not_called()


class WorkspaceActionGuardTests(unittest.TestCase):
    def test_lock_refuses_duplicate(self):
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=True)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "already locked"):
                h.hcp_terraform_lock_workspace({"workspace_id": "ws-test"}, None)
            api.assert_not_called()

    def test_unlock_refuses_duplicate(self):
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=False)), \
             mock.patch.object(h, "_api") as api:
            with self.assertRaisesRegex(RuntimeError, "already unlocked"):
                h.hcp_terraform_unlock_workspace({"workspace_id": "ws-test"}, None)
            api.assert_not_called()

    def test_lock_returns_provider_state(self):
        locked = workspace(locked=True, reason="maintenance")
        with mock.patch.object(h, "_get_workspace", return_value=workspace(locked=False)), \
             mock.patch.object(h, "_api", return_value=(200, {"data": locked}, {})):
            result, _ = h.hcp_terraform_lock_workspace({"workspace_id": "ws-test", "reason": "maintenance"}, None)
            self.assertTrue(result["locked"])
            self.assertEqual(result["action"], "lock")


if __name__ == "__main__":
    unittest.main()
