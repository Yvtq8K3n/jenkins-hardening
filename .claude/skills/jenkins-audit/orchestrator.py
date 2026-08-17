#!/usr/bin/env python3
"""
Jenkins Hardening Audit Orchestrator

Coordinates four independent audit agents:
- jenkins-howtoharden
- jenkins-official-security
- jenkins-owasp-cicd
- jenkins-orphan-hygiene

Generates shared timestamp, launches agents in parallel, collects results, renders report.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime


def load_env_file(env_file):
    """Load .env file manually without external dependencies."""
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()


def load_credentials():
    """Load Jenkins credentials from .env or environment variables, prompting for missing values."""
    env_file = Path.cwd() / ".env"
    load_env_file(env_file)

    jenkins_url = os.getenv("JENKINS_URL")
    jenkins_user = os.getenv("JENKINS_USER")
    jenkins_token = os.getenv("JENKINS_TOKEN")

    if not jenkins_url:
        jenkins_url = input("Enter Jenkins URL (e.g., https://jenkins.example.com): ").strip()
        if not jenkins_url:
            print("Error: Jenkins URL is required")
            sys.exit(1)

    if not jenkins_user:
        jenkins_user = input("Enter Jenkins username: ").strip()
        if not jenkins_user:
            print("Error: Jenkins username is required")
            sys.exit(1)

    if not jenkins_token:
        jenkins_token = input("Enter Jenkins API token: ").strip()
        if not jenkins_token:
            print("Error: Jenkins API token is required")
            sys.exit(1)

    return jenkins_url, jenkins_user, jenkins_token


def generate_timestamp():
    """Generate UTC timestamp for report naming."""
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def create_reports_dir():
    """Ensure reports directory exists."""
    reports_dir = Path.cwd() / "reports"
    reports_dir.mkdir(exist_ok=True)
    return reports_dir


def launch_agents(timestamp, jenkins_url, jenkins_user, jenkins_token):
    """
    Launch four audit agents in parallel using Claude Code's agent teams.

    Each agent writes its findings to a JSON file named:
    - reports/jenkins-audit-{timestamp}-howtoharden.json
    - reports/jenkins-audit-{timestamp}-official-security.json
    - reports/jenkins-audit-{timestamp}-owasp-cicd.json
    - reports/jenkins-audit-{timestamp}-orphan-hygiene.json

    Agent names include the timestamp to ensure uniqueness across multiple invocations,
    preventing team bloat when the skill is re-invoked.

    Credentials are passed explicitly to each agent as prompt parameters,
    so they can pass them as --jenkins-url / --username / --token flags
    to jenkins_api.py on every call. This ensures they work correctly in
    teammate mode (separate processes) where environment variables don't propagate.

    Returns the file paths where agents will write their output and prompts for each agent.
    """
    reports_dir = create_reports_dir()

    output_files = {
        "howtoharden": reports_dir / f"jenkins-audit-{timestamp}-howtoharden.json",
        "official-security": reports_dir / f"jenkins-audit-{timestamp}-official-security.json",
        "owasp-cicd": reports_dir / f"jenkins-audit-{timestamp}-owasp-cicd.json",
        "orphan-hygiene": reports_dir / f"jenkins-audit-{timestamp}-orphan-hygiene.json",
    }

    # Agent names include timestamp to avoid conflicts when skill is re-invoked
    agent_names = {
        "howtoharden": f"audit-howtoharden-{timestamp}",
        "official-security": f"audit-official-security-{timestamp}",
        "owasp-cicd": f"audit-owasp-cicd-{timestamp}",
        "orphan-hygiene": f"audit-orphan-hygiene-{timestamp}",
    }

    # Prepare agent prompts with explicit credential parameters
    prompts = {
        "jenkins-howtoharden": f"""
Run a Jenkins security audit against the howtoharden.com guide.

Target: {jenkins_url}

Jenkins credentials (pass these explicitly on every jenkins_api.py call — do not rely
on environment variables, since you may be running in a separate process from the team lead):
  --jenkins-url {jenkins_url}
  --username {jenkins_user}
  --token {jenkins_token}

Example: python3 jenkins_api.py --jenkins-url {jenkins_url} --username {jenkins_user} --token {jenkins_token} info

Write your findings to this exact file path when done:
{output_files['howtoharden']}

Follow the checklist in your agent definition and output valid JSON matching the schema.

After writing the JSON file, send the team lead a confirmation message with:
1. Audit name (e.g., "howtoharden audit complete")
2. Number of controls and summary (e.g., "Wrote 24 controls")
3. An ASCII box-drawing table breaking down controls by category, with columns: Category | PASS | FAIL | MANUAL | Total

Use this exact style for the table (with box-drawing characters ┌─┬─┐ etc):
```
┌──────────────────────────────────────┬──────┬──────┬────────┬───────┐
│ Category                              │ PASS │ FAIL │ MANUAL │ Total │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ Category Name                         │ N    │ N    │ N      │ N     │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ TOTAL                                 │ N    │ N    │ N      │ N     │
└──────────────────────────────────────┴──────┴──────┴────────┴───────┘
```

Include this table in your message to SendMessage.
""",
        "jenkins-official-security": f"""
Run a Jenkins security audit against the official Jenkins.io Securing Jenkins book.

Target: {jenkins_url}

Jenkins credentials (pass these explicitly on every jenkins_api.py call — do not rely
on environment variables, since you may be running in a separate process from the team lead):
  --jenkins-url {jenkins_url}
  --username {jenkins_user}
  --token {jenkins_token}

Example: python3 jenkins_api.py --jenkins-url {jenkins_url} --username {jenkins_user} --token {jenkins_token} info

Write your findings to this exact file path when done:
{output_files['official-security']}

Follow the checklist in your agent definition and output valid JSON matching the schema.

After writing the JSON file, send the team lead a confirmation message with:
1. Audit name (e.g., "official-security audit complete")
2. Number of controls and summary (e.g., "Wrote 15 controls")
3. An ASCII box-drawing table breaking down controls by category, with columns: Category | PASS | FAIL | MANUAL | Total

Use this exact style for the table (with box-drawing characters ┌─┬─┐ etc):
```
┌──────────────────────────────────────┬──────┬──────┬────────┬───────┐
│ Category                              │ PASS │ FAIL │ MANUAL │ Total │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ Category Name                         │ N    │ N    │ N      │ N     │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ TOTAL                                 │ N    │ N    │ N      │ N     │
└──────────────────────────────────────┴──────┴──────┴────────┴───────┘
```

Include this table in your message to SendMessage.
""",
        "jenkins-owasp-cicd": f"""
Run a Jenkins security audit against the OWASP Top 10 CI/CD Security Risks.

Target: {jenkins_url}

Jenkins credentials (pass these explicitly on every jenkins_api.py call — do not rely
on environment variables, since you may be running in a separate process from the team lead):
  --jenkins-url {jenkins_url}
  --username {jenkins_user}
  --token {jenkins_token}

Example: python3 jenkins_api.py --jenkins-url {jenkins_url} --username {jenkins_user} --token {jenkins_token} info

Write your findings to this exact file path when done:
{output_files['owasp-cicd']}

Follow the checklist in your agent definition and output valid JSON matching the schema.

After writing the JSON file, send the team lead a confirmation message with:
1. Audit name (e.g., "owasp-cicd audit complete")
2. Number of controls and summary (e.g., "Wrote 10 controls")
3. An ASCII box-drawing table breaking down controls by category, with columns: Category | PASS | FAIL | MANUAL | Total

Use this exact style for the table (with box-drawing characters ┌─┬─┐ etc):
```
┌──────────────────────────────────────┬──────┬──────┬────────┬───────┐
│ Category                              │ PASS │ FAIL │ MANUAL │ Total │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ Category Name                         │ N    │ N    │ N      │ N     │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ TOTAL                                 │ N    │ N    │ N      │ N     │
└──────────────────────────────────────┴──────┴──────┴────────┴───────┘
```

Include this table in your message to SendMessage.
""",
        "jenkins-orphan-hygiene": f"""
Run a Jenkins audit for orphaned jobs, stale pipelines, dormant accounts, and dead infrastructure.

Target: {jenkins_url}

Jenkins credentials (pass these explicitly on every jenkins_api.py call — do not rely
on environment variables, since you may be running in a separate process from the team lead):
  --jenkins-url {jenkins_url}
  --username {jenkins_user}
  --token {jenkins_token}

Example: python3 jenkins_api.py --jenkins-url {jenkins_url} --username {jenkins_user} --token {jenkins_token} info

Write your findings to this exact file path when done:
{output_files['orphan-hygiene']}

Follow the checklist in your agent definition and output valid JSON matching the schema.

After writing the JSON file, send the team lead a confirmation message with:
1. Audit name (e.g., "orphan-hygiene audit complete")
2. Number of controls and summary (e.g., "Wrote 13 controls")
3. An ASCII box-drawing table breaking down controls by category, with columns: Category | PASS | FAIL | MANUAL | Total

Use this exact style for the table (with box-drawing characters ┌─┬─┐ etc):
```
┌──────────────────────────────────────┬──────┬──────┬────────┬───────┐
│ Category                              │ PASS │ FAIL │ MANUAL │ Total │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ Category Name                         │ N    │ N    │ N      │ N     │
├──────────────────────────────────────┼──────┼──────┼────────┼───────┤
│ TOTAL                                 │ N    │ N    │ N      │ N     │
└──────────────────────────────────────┴──────┴──────┴────────┴───────┘
```

Include this table in your message to SendMessage.
""",
    }

    # Print instructions for the user to spawn the agents
    print("\n" + "="*70)
    print("JENKINS AUDIT ORCHESTRATOR")
    print("="*70)
    print(f"\nTimestamp: {timestamp}")
    print(f"Target: {jenkins_url}")
    print(f"Reports directory: {reports_dir}")
    print("\nFour audit agents will run in parallel:")
    print("  • jenkins-howtoharden")
    print("  • jenkins-official-security")
    print("  • jenkins-owasp-cicd")
    print("  • jenkins-orphan-hygiene")
    print("\nAgent teams mode is ENABLED. You should see four panes in your terminal.")
    print("Agent names include timestamp to prevent team bloat on re-invocation.")
    print("Credentials are passed explicitly to each agent via prompt parameters.")
    print("\nSpawning agents in 3 seconds...\n")

    return output_files, prompts, agent_names


def render_report(output_files, timestamp):
    """
    Render the final HTML report from four JSON inputs.

    Calls render_report.py with the four JSON files.
    """
    reports_dir = Path.cwd() / "reports"
    html_output = reports_dir / f"jenkins-audit-{timestamp}.html"

    render_script = Path.cwd() / ".claude/skills/jenkins-audit/render_report.py"

    if not render_script.exists():
        print(f"Error: render_report.py not found at {render_script}")
        return None

    cmd = [
        "python3",
        str(render_script),
        str(output_files["howtoharden"]),
        str(output_files["official-security"]),
        str(output_files["owasp-cicd"]),
        str(output_files["orphan-hygiene"]),
        "--out",
        str(html_output),
    ]

    print(f"\nRendering HTML report...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error rendering report: {result.stderr}")
        return None

    print(result.stdout)
    return html_output


def verify_output_files(output_files):
    """Verify all three JSON output files exist."""
    missing = []
    for name, path in output_files.items():
        if not Path(path).exists():
            missing.append(f"{name}: {path}")

    if missing:
        print("\nError: The following output files were not created:")
        for m in missing:
            print(f"  • {m}")
        return False

    return True


def verify_gitignore():
    """Warn if .env is not in .gitignore to prevent credential leaks."""
    gitignore_path = Path.cwd() / ".gitignore"
    if gitignore_path.exists():
        content = gitignore_path.read_text()
        if ".env" not in content:
            print("Warning: .env not in .gitignore. Consider adding it to prevent accidental credential commits.")
    else:
        print("Warning: .gitignore not found. Create one with '.env' to prevent credential leaks.")


def main():
    """Main orchestrator flow."""
    # Parse command-line arguments: [jenkins-url] [--insecure]
    jenkins_url_arg = None
    insecure = False

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--insecure":
            insecure = True
        elif not arg.startswith("--"):
            jenkins_url_arg = arg

    verify_gitignore()
    print("Loading credentials...")
    jenkins_url, jenkins_user, jenkins_token = load_credentials()

    # Override URL if provided as argument
    if jenkins_url_arg:
        jenkins_url = jenkins_url_arg

    # Set environment for agents (fallback for legacy code paths)
    os.environ["JENKINS_URL"] = jenkins_url
    os.environ["JENKINS_USER"] = jenkins_user
    os.environ["JENKINS_TOKEN"] = jenkins_token

    timestamp = generate_timestamp()
    output_files, prompts, agent_names = launch_agents(
        timestamp, jenkins_url, jenkins_user, jenkins_token
    )

    print("Orchestrator complete. Waiting for agents to finish...")
    print("\nIMPORTANT: Agent teams mode requires CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1")
    print("This orchestrator returns control to Claude Code, which will spawn the four agents.")
    print("\nOnce all agents finish and send confirmation messages, the report will be rendered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
