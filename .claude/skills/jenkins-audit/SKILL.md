---
name: jenkins-audit
description: Run a multi-agent Jenkins hardening audit
subagent_type: None
---

When invoked, this skill automatically runs the Jenkins audit orchestrator. See documentation below.

# /jenkins-audit Skill

This skill orchestrates four independent audit agents to evaluate a Jenkins instance
against three security benchmarks (howtoharden.com, Jenkins.io official security, OWASP Top 10 CI/CD) plus
a fourth agent for operational-lifecycle hygiene (orphaned jobs, dormant accounts, dead infrastructure).

## Invocation

```
/jenkins-audit [jenkins-url] [--insecure]
```

- If `JENKINS_URL` is already configured in your `.env` file, you can simply run `/jenkins-audit` with no arguments.
- If you want to override the `.env` URL for a one-time run, pass the URL as an argument (e.g., `/jenkins-audit https://jenkins.example.com`).
- The team lead's `.env` file (or environment variables) is the source of truth for all credentials.

## How It Works

1. **Gather credentials** (team lead only): Load from `.env` file first, then environment variables. Only prompt for any missing credentials.
   This ensures you're not prompted if you've already configured your credentials in `.env`.

2. **Generate shared timestamp**: Create one UTC timestamp (e.g., `20260816-143200`) that will be used
   to name all five artifacts produced by this run.

3. **Pass credentials to agents**: The resolved `JENKINS_URL`, `JENKINS_USER`, and `JENKINS_TOKEN` are passed
   directly in each teammate's launch prompt (as `--jenkins-url`, `--username`, `--token` flags).
   Teammates receive these explicit parameters and pass them on every `jenkins_api.py` call, ensuring authentication
   works correctly even in separate processes where environment-variable inheritance is unreliable.

4. **Launch four audit agents in parallel**:

   **Default mode** (when `$CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` is not set, or is `0`):
   Launch as background subagents. Each agent is given an absolute path to its output JSON file:
   - `jenkins-howtoharden` — audits against the howtoharden.com guide, writes to `reports/jenkins-audit-<TS>-howtoharden.json`
   - `jenkins-official-security` — audits against Jenkins.io official security book, writes to `reports/jenkins-audit-<TS>-official-security.json`
   - `jenkins-owasp-cicd` — audits against OWASP Top 10 CI/CD risks, writes to `reports/jenkins-audit-<TS>-owasp-cicd.json`
   - `jenkins-orphan-hygiene` — audits for orphaned jobs, stale pipelines, dormant accounts, and dead infrastructure, writes to `reports/jenkins-audit-<TS>-orphan-hygiene.json`

   The four subagent calls return task-notifications once each completes; the orchestrator proceeds to step 4 once all four notifications have arrived.

   **Teammate mode** (when `$CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` is set to `1`):
   Launch as visible teammates in tmux panes (or your configured display mode). Use unique agent names
   that include the timestamp to avoid conflicts when re-invoking the skill (e.g., `name="audit-howtoharden-<TS>"`, etc.).
   Call the Agent tool with the `name` parameter for each agent in addition to the `subagent_type`.
   Each teammate is instructed to:
   1. Gather evidence and write its findings to the given JSON file path (same as above).
   2. After writing, send the team lead a brief confirmation message via `SendMessage` (since a named Agent
      call with teams enabled does not block-return the way a subagent call does).

   The orchestrator then waits for four incoming messages (one per teammate) before proceeding to step 4.

4. **Collect results**:

   **Default mode**: After all four subagent notifications have arrived, verify all four JSON files exist.
   If any is missing or an agent reported a write failure, stop and report the error to the user.

   **Teammate mode**: After receiving four `SendMessage` confirmations from the teammates (the team lead's
   inbox will receive one message per teammate once they finish), verify all four JSON files exist. If any
   is missing or a teammate reported a write failure, stop and report the error to the user.

5. **Render the report**: Invoke the `/jenkins-gen-report` skill to combine the four JSON files into one
   polished HTML report. The skill will:
   - Auto-detect the latest audit JSONs from `reports/`
   - Render to `reports/jenkins-gen-report-<TS>.html`
   - Include warnings if any benchmark is incomplete

   Users can also invoke this skill independently to re-render or force incomplete reports:
   ```bash
   /jenkins-gen-report --skip-validation
   ```

6. **Report the result**: Tell the user the HTML report path, the four JSON artifact paths, and a summary
   of totals. Do **not** publish as an Artifact by default (local file only, since it's a live security posture report).

## Teammate Mode (Experimental)

This skill supports Claude Code's **experimental Agent Teams** feature, which lets you see the four audit agents
working in parallel as visible panes in your terminal (tmux, iTerm2, etc.).

**To enable teammate mode:**
1. Set the environment variable: `export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`
2. Launch Claude Code with teammate display: `claude --teammate-mode tmux` (or your preferred mode)
3. Run `/jenkins-audit <jenkins-url>` as usual

When teammate mode is active, four panes will appear (three security benchmarks + one hygiene agent), each showing the agent's
output in real time. Once all four complete and their JSON files are written, the orchestrator proceeds
to render the HTML report.

**Credential Flow in Teammate Mode:**
The team lead resolves credentials once (from `.env`, env vars, or interactive prompt — `.env` is checked first).
The orchestrator then passes the resolved credentials directly to each teammate as explicit `--jenkins-url`,
`--username`, and `--token` parameters in their task prompt. Teammates pass these flags on every `jenkins_api.py` call,
ensuring authentication works correctly even in separate processes where environment-variable inheritance is unreliable.
Teammates do not need their own `.env` file or environment variables — the lead supplies everything they need up front.

**When teammate mode is not active** (the default), the four agents run as background subagents with no
visible panes — the audit still completes normally, just without the real-time visibility.

**Note:** Teammate mode is marked as experimental by Claude Code and is subject to change. If you encounter
issues with the `name` parameter or message passing, please check the
[official documentation](https://code.claude.com/docs/en/agent-teams) for the latest details.

**Team Size Management:** Agent names include the audit timestamp to ensure uniqueness. This prevents team bloat
when re-invoking the skill—each run creates a fresh set of agents with unique names (e.g., `audit-howtoharden-20260816-143200`)
rather than reusing or conflicting with previous runs.

**Marker File (`.marker`):** The orchestrator writes a JSON file to `.claude/skills/jenkins-audit/.marker` tracking:
- `timestamp` — UTC timestamp for the current audit run
- `output_files` — paths to the 4 JSON artifacts (howtoharden, official-security, owasp-cicd, orphan-hygiene)
- `agent_names` — unique agent names for the current run

This file is useful if you need to reference agent outputs programmatically or track multiple audit runs.

## Environment Setup

The skill reads credentials from `.env` file first, then environment variables. You can configure credentials in one of three ways:

**Preferred: `.env` file** (no prompts on repeated runs):
```bash
# .env in the project root
JENKINS_URL=https://jenkins.example.com
JENKINS_USER=audit-bot
JENKINS_TOKEN=<your-api-token>
```

**Alternative: Environment variables**:
```bash
export JENKINS_URL=https://jenkins.example.com
export JENKINS_USER=audit-bot
export JENKINS_TOKEN=<your-api-token>
```

**Interactive: Let the skill prompt you** (if credentials are missing):
Simply run `/jenkins-audit` and enter credentials when prompted.

The skill checks for credentials in this order: `.env` file → environment variables → interactive prompt.

## Control Status Vocabulary

Each control in the audit receives one of four statuses:

| Status | Meaning | Action |
|--------|---------|--------|
| **PASS** | Control is objectively satisfied (e.g., security enabled, anonymous denied) | None; document as compliant |
| **FAIL** | Automated check reveals a clear gap (e.g., HTTP-only, builds on controller, missing plugin) | **HIGH PRIORITY** — remediate per guidance |
| **MANUAL** | Requires human judgment, code review, or manual verification (e.g., auth strategy, script queue) | Schedule review; verify per guidance |
| **LACK PRIVS** | API returned 403/401; insufficient credentials to complete the check | Re-run with elevated credentials to verify |

## Output

Each audit run produces five files, all sharing one UTC timestamp:

1. **`reports/jenkins-audit-<TS>-howtoharden.json`** — Machine-parseable evidence from the howtoharden.com audit
2. **`reports/jenkins-audit-<TS>-official-security.json`** — Machine-parseable evidence from the Jenkins.io audit
3. **`reports/jenkins-audit-<TS>-owasp-cicd.json`** — Machine-parseable evidence from the OWASP CI/CD audit
4. **`reports/jenkins-audit-<TS>-orphan-hygiene.json`** — Machine-parseable evidence from the operational-hygiene audit
5. **`reports/jenkins-audit-<TS>.html`** — Self-contained HTML report combining all four audits

The HTML report includes:
- Metadata header (target URL, audit timestamp, audit user, benchmarks audited)
- Executive summary with stat tiles and a horizontal stacked-bar chart showing PASS/FAIL/MANUAL breakdown per benchmark
- Unified control checklist (all controls from all four benchmarks in one scannable table)
- Detailed findings by benchmark (collapsible sections per status: FAIL, MANUAL, PASS)
- Prioritized remediation roadmap (FAIL items first, MANUAL items grouped by benchmark)
- Audit methodology footer with links to each benchmark's source URL

The JSON files are durable, machine-parseable evidence artifacts suitable for CI/CD automation, diffing
across runs, or re-rendering. The HTML report is self-contained (no external network calls, inline CSS/SVG)
and opens offline in any browser. Both are suitable for manual review or sharing; neither is published as
a Claude Code Artifact by default.
