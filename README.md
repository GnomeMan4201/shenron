# aish — AI Session Handoff CLI

**Local-first CLI for preserving, summarising, archiving, and handing off long AI browser conversations.**

Built for legitimate personal workflow continuity when switching between AI accounts or models.

---

## Design principles

- **Local-first** — all data in SQLite at `~/.local/share/aish/`
- **No credential capture** — passwords, cookies, and tokens are never touched
- **No stealth scraping** — everything requires your action
- **Human-confirmed** — destructive or browser-launching actions ask first
- **Plain text output** — Markdown, JSON, and text; all replayable and auditable
- **Browser-optional** — the browser integration only opens profiles; you log in yourself

---

## Install

```bash
git clone https://github.com/you/ai-session-handoff
cd ai-session-handoff
pip install -e .          # standard install
# or with optional browser support:
pip install -e ".[browser]"
```

After install, `aish` is on your PATH.

---

## Typical workflow

### 1. Start a session

```bash
aish session start \
  --project "Prompts That Survive Pressure" \
  --provider claude \
  --model "Claude Sonnet" \
  --account "claude-main"
```

### 2. Add notes as you work

```bash
aish note "Started Prompt 6: drafting 12 flagship prompts"
aish note "Agreed on 3-part structure: hook, body, close"
```

### 3. Capture the conversation

When you hit a usage limit or want to checkpoint:

```bash
aish capture paste      # opens $EDITOR — paste your conversation, save and close
aish capture file --file ~/Downloads/conversation.txt   # import a file
cat transcript.txt | aish capture stdin                 # pipe from stdin
```

### 4. Generate a summary request

```bash
aish summarize
```

This prints a structured prompt. Copy it and paste it into your AI chat.
The model will respond with a formatted summary. Then store it:

```bash
aish summarize --paste-back   # opens $EDITOR — paste the AI's summary, save
```

### 5. Generate the handoff packet

```bash
aish handoff
```

This produces a complete continuation prompt assembled from:
- The stored summary
- All your notes
- The last ~3 000 characters of the conversation

It's printed to the terminal and stored in the database.

### 6. Save everything to disk

```bash
aish save
```

Exports to `~/.local/share/aish/sessions/<uuid>/`:
```
notes.md
capture_01.txt
summary.md
handoff.md
save_report.md
```

### 7. Close the session

```bash
aish close
```

Marks the session closed. If no handoff exists you'll be warned.

### 8. Open the next browser profile (optional)

```bash
aish browser open --profile "claude-backup-1" --browser brave
```

This **only launches the browser**. It does not log in or automate anything.

### 9. Start the next session and resume

```bash
aish session start \
  --project "Prompts That Survive Pressure" \
  --provider claude \
  --account "claude-backup-1" \
  --model "Claude Sonnet"

aish handoff --show --latest   # prints the continuation prompt
```

Copy the handoff prompt and paste it into your new chat. Done.

---

## Command reference

### Session commands

| Command | Description |
|---|---|
| `aish session start` | Start a new session |
| `aish session list` | List sessions (filter by `--status`, `--project`) |
| `aish session show [ID]` | Show full details for a session |
| `aish session status` | Quick status of the current open session |

### Workflow commands

| Command | Description |
|---|---|
| `aish note "text"` | Add a timestamped note to the current session |
| `aish capture paste` | Open editor to paste a conversation transcript |
| `aish capture file --file PATH` | Import a transcript file |
| `aish capture stdin` | Read transcript from stdin |
| `aish summarize` | Print a summary request prompt to paste into the AI |
| `aish summarize --paste-back` | Store an AI-generated summary |
| `aish handoff` | Generate and store a continuation packet |
| `aish handoff --show` | Print the most recent handoff packet |
| `aish save` | Export all session data to disk |
| `aish close` | Mark the current session as closed |

### Browser commands

| Command | Description |
|---|---|
| `aish browser open --profile NAME` | Open a browser profile (no login automation) |
| `aish browser list-profiles` | List known local browser profiles |

### Utility

| Command | Description |
|---|---|
| `aish info` | Show data directory and DB paths |
| `aish version` | Print version |

---

## Data directory

Default: `~/.local/share/aish/`

Override with `--data-dir PATH` or `AISH_DATA_DIR` environment variable.

```
~/.local/share/aish/
├── aish.db                  # SQLite database (all session metadata)
└── sessions/
    └── <session-uuid>/
        ├── notes.md
        ├── capture_01.txt
        ├── summary.md
        ├── handoff.md
        └── save_report.md
```

---

## Safety guarantees

This tool is designed for legitimate personal workflow continuity.

- ❌ Does not capture passwords
- ❌ Does not read browser cookies or session tokens  
- ❌ Does not bypass login flows
- ❌ Does not automate browser actions without explicit user confirmation
- ❌ Does not rely on hidden browser internals or undocumented APIs
- ✅ All captured text is text you paste yourself
- ✅ Browser integration only opens a profile window
- ✅ Every action is logged locally and auditable

---

## Development

```bash
pip install -e ".[dev]"
pytest                          # run all tests
pytest tests/test_repository.py # run specific file
```

---

## Roadmap (v2 ideas)

- `aish export --format json` — machine-readable export
- `aish project list` — view all projects across sessions
- `aish search "keyword"` — full-text search across captures
- Playwright-based safe page snapshot (user-approved, not scraped)
- Shell completions (`aish --install-completion`)
