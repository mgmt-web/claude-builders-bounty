#!/usr/bin/env python3
"""
Claude Code PreToolUse guard for destructive Bash commands.

Reads a Claude Code hook event as JSON from stdin. For Bash tool calls,
blocks high-risk destructive commands and logs each blocked attempt to:
    ~/.claude/hooks/blocked.log

Blocked patterns required by the bounty:
- rm -rf
- DROP TABLE
- git push --force / git push -f
- TRUNCATE
- DELETE FROM without a WHERE clause
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
import re
import sys
from typing import Optional

LOG_PATH = Path.home() / ".claude" / "hooks" / "blocked.log"

RM_RF_RE = re.compile(r"(?i)(?:^|[;&|()\s])rm\s+(?:-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*)(?:\s|$)")
DROP_TABLE_RE = re.compile(r"(?is)\bdrop\s+table\b")
GIT_FORCE_RE = re.compile(r"(?i)\bgit\s+push\b[^\n;&|]*?(?:--force(?:-with-lease)?|-f)(?:\s|$)")
TRUNCATE_RE = re.compile(r"(?is)\btruncate(?:\s+table)?\b")
DELETE_RE = re.compile(r"(?is)\bdelete\s+from\b")


def _delete_without_where(command: str) -> bool:
    """Return True if any DELETE FROM statement lacks a WHERE clause.

    We conservatively split on common shell/SQL statement separators, then
    inspect each DELETE statement independently.
    """
    for statement in re.split(r"[;\n]+", command):
        if DELETE_RE.search(statement) and not re.search(r"(?is)\bwhere\b", statement):
            return True
    return False


def blocked_reason(command: str) -> Optional[str]:
    """Return a human-readable blocking reason, or None when allowed."""
    checks = (
        (RM_RF_RE, "recursive forced deletion (`rm -rf`)"),
        (DROP_TABLE_RE, "destructive SQL (`DROP TABLE`)"),
        (GIT_FORCE_RE, "history-rewriting push (`git push --force`/`-f`)"),
        (TRUNCATE_RE, "destructive SQL (`TRUNCATE`)"),
    )
    for pattern, reason in checks:
        if pattern.search(command):
            return reason

    if _delete_without_where(command):
        return "destructive SQL (`DELETE FROM` without a `WHERE` clause)"
    return None


def log_block(command: str, project_path: str, reason: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
    safe_command = command.replace("\n", "\\n")
    safe_project = project_path.replace("\n", "\\n")
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"{ts}\tproject={safe_project}\treason={reason}\tcommand={safe_command}\n")


def deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"Blocked destructive command: {reason}. "
                "Use a safer, scoped alternative or ask the user for explicit approval."
            ),
        }
    }))


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0

    if event.get("tool_name") != "Bash":
        return 0

    tool_input = event.get("tool_input") or {}
    command = str(tool_input.get("command") or "")
    if not command.strip():
        return 0

    reason = blocked_reason(command)
    if reason is None:
        return 0

    project_path = (
        str(event.get("cwd") or "")
        or str(tool_input.get("cwd") or "")
        or os.getcwd()
    )
    try:
        log_block(command, project_path, reason)
    except OSError:
        pass

    deny(reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
