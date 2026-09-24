import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / ".claude" / "hooks" / "destructive_bash_guard.py"
spec = importlib.util.spec_from_file_location("guard", MODULE_PATH)
guard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_required_blocks(self):
        blocked = [
            "rm -rf build/",
            "rm -fr build/",
            "DROP TABLE users;",
            "git push --force origin main",
            "git push -f origin main",
            "git push --force-with-lease origin main",
            "TRUNCATE TABLE audit_log;",
            "DELETE FROM users;",
            "delete from sessions",
        ]
        for command in blocked:
            with self.subTest(command=command):
                self.assertIsNotNone(guard.blocked_reason(command))

    def test_safe_commands_allowed(self):
        allowed = [
            "rm build/output.txt",
            "git push origin feature/x",
            "SELECT * FROM users",
            "DELETE FROM users WHERE id = 42;",
            "echo hello",
            "python -m pytest",
        ]
        for command in allowed:
            with self.subTest(command=command):
                self.assertIsNone(guard.blocked_reason(command))

    def test_delete_where_is_checked_per_statement(self):
        self.assertIsNotNone(
            guard.blocked_reason("DELETE FROM a WHERE id=1; DELETE FROM b;")
        )
        self.assertIsNone(
            guard.blocked_reason("DELETE FROM a WHERE id=1; DELETE FROM b WHERE id=2;")
        )

    def test_blocked_attempt_is_logged_and_denied(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "blocked.log"
            event = {
                "tool_name": "Bash",
                "cwd": "/tmp/example-project",
                "tool_input": {"command": "git push --force origin main"},
            }
            with patch.object(guard, "LOG_PATH", log_path), \
                 patch("sys.stdin", io.StringIO(json.dumps(event))), \
                 patch("sys.stdout", new_callable=io.StringIO) as stdout:
                rc = guard.main()

            self.assertEqual(rc, 0)
            response = json.loads(stdout.getvalue())
            specific = response["hookSpecificOutput"]
            self.assertEqual(specific["hookEventName"], "PreToolUse")
            self.assertEqual(specific["permissionDecision"], "deny")
            self.assertIn("Blocked destructive command", specific["permissionDecisionReason"])

            logged = log_path.read_text(encoding="utf-8")
            self.assertIn("git push --force origin main", logged)
            self.assertIn("/tmp/example-project", logged)

    def test_non_bash_tool_is_ignored(self):
        event = {"tool_name": "Read", "tool_input": {"command": "rm -rf /tmp/x"}}
        with patch("sys.stdin", io.StringIO(json.dumps(event))), \
             patch("sys.stdout", new_callable=io.StringIO) as stdout:
            rc = guard.main()
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue(), "")

    def test_normal_bash_command_is_ignored(self):
        event = {"tool_name": "Bash", "tool_input": {"command": "echo safe"}}
        with patch("sys.stdin", io.StringIO(json.dumps(event))), \
             patch("sys.stdout", new_callable=io.StringIO) as stdout:
            rc = guard.main()
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
