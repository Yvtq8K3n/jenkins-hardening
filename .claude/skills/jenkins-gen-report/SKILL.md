---
name: jenkins-gen-report
description: Render Jenkins audit JSON findings into an interactive HTML report
---

Render Jenkins audit findings from JSON files into a self-contained HTML report.

## Invocation

```bash
/jenkins-gen-report [--skip-validation] [--json-dir <path>] [--out <path>]
```

**Options:**
- `--skip-validation` — Proceed even if some JSON files are missing; include warnings in HTML for incomplete data sources
- `--json-dir <path>` — Directory containing JSON audit files (default: `reports/`)
- `--out <path>` — Output HTML file path (default: `reports/jenkins-gen-report-<timestamp>.html`)

## Behavior

### Default (no arguments)
```bash
/jenkins-gen-report
```
- Scans `reports/` for the most recent set of four audit JSONs (howtoharden, official-security, owasp-cicd, orphan-hygiene)
- If all four are found: renders HTML silently
- If any are missing and `--skip-validation` not provided: **prompts user** — "Some audit sources are missing. Render incomplete report? (y/n)"
- If user declines: exits with no changes
- If user accepts or `--skip-validation` provided: renders HTML with prominent warnings for missing sources

### With --skip-validation
```bash
/jenkins-gen-report --skip-validation
```
- Same as above, but skips the user prompt and renders incomplete reports immediately
- HTML header includes: "⚠️ This report is incomplete. Missing data from: howtoharden, orphan-hygiene"

### Custom JSON paths
```bash
/jenkins-gen-report reports/jenkins-audit-20260815-howtoharden.json reports/jenkins-audit-20260815-official-security.json reports/jenkins-audit-20260815-owasp-cicd.json reports/jenkins-audit-20260815-orphan-hygiene.json
```
- Uses exactly the provided JSON files (must be four paths)
- Validates each file exists before rendering

### Custom output location
```bash
/jenkins-gen-report --out my-report.html
```
- Renders to the specified path instead of default

## Output

Produces a self-contained HTML report (no external dependencies) with:
- Metadata header (target URL, audit timestamp, audit user, benchmarks audited)
- Executive summary with stat tiles and stacked-bar charts
- Unified control checklist (all controls, all benchmarks)
- Detailed findings by benchmark (collapsible, per status)
- Prioritized remediation roadmap
- Audit methodology footer

If any source is missing, the HTML includes:
- Red warning banner at top: "⚠️ Incomplete Report"
- List of missing benchmarks with explanation
- Note: "This report should not be used for compliance decisions without all data sources"
- Partial checklists/summaries only for available benchmarks

## Use Cases

**Re-render a past audit with different options:**
```bash
/jenkins-gen-report --json-dir reports/ --skip-validation --out reports/audit-review.html
```

**Generate an incomplete report after a failed audit:**
```bash
/jenkins-gen-report --skip-validation
# Renders what's available; useful for troubleshooting mid-audit
```

**Force rendering from a specific audit run:**
```bash
/jenkins-gen-report reports/jenkins-audit-20260815-*.json
```

## Integration with /jenkins-audit

The orchestrator will invoke this skill after all four agents complete:
```python
Skill("jenkins-gen-report")  # Auto-detects latest JSONs
```

Users can also invoke independently to re-render or force incomplete reports.
