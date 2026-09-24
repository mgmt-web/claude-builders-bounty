# Destructive Bash Guard for Claude Code

A lightweight `PreToolUse` hook that blocks destructive Bash commands before Claude Code executes them.

## What it blocks

- `rm -rf` (including combined flags such as `rm -fr`)
- `DROP TABLE`
- `git push --force`, `git push --force-with-lease`, and `git push -f`
- `TRUNCATE` / `TRUNCATE TABLE`
- `DELETE FROM ...` when the statement has no `WHERE` clause

Every blocked attempt is appended to `~/.claude/hooks/blocked.log`. Each entry contains a UTC timestamp, attempted command, project path, and blocking reason.

## Install — 2 commands

```bash
mkdir -p ~/.claude/hooks && cp .claude/hooks/destructive_bash_guard.py ~/.claude/hooks/destructive_bash_guard.py && chmod +x ~/.claude/hooks/destructive_bash_guard.py
```

```bash
python - <<'PY'
import json, pathlib
p = pathlib.Path.home()/".claude/settings.json"
d = json.loads(p.read_text()) if p.exists() else {}
d.setdefault("hooks", {}).setdefault("PreToolUse", []).append({
    "matcher": "Bash",
    "hooks": [{"type": "command", "command": str(pathlib.Path.home()/".claude/hooks/destructive_bash_guard.py")}]
})
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(d, indent=2) + "\n")
PY
```

## Examples

Blocked:
```bash
rm -rf build/
git push --force origin main
psql -c 'DROP TABLE users'
sqlite3 app.db 'TRUNCATE TABLE events'
psql -c 'DELETE FROM users'
```

Allowed:
```bash
rm build/output.txt
git push origin feature/safe-branch
psql -c 'DELETE FROM sessions WHERE expires_at < now()'
echo "normal command"
```

## Test

```bash
python -m unittest -v tests/test_destructive_bash_guard.py
```

The test suite covers all required blocked patterns, safe commands, non-Bash calls, logging, and the deny response.

## Notes

Pattern matching is a guardrail, not a complete shell parser. Claude Code's normal permission system remains in place for commands the hook does not block.
