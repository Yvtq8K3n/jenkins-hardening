#!/usr/bin/env python3
"""
Wrapper to render Jenkins audit JSONs into HTML with smart defaults.

- Auto-detects latest audit JSONs if none provided
- Prompts user if incomplete (unless --skip-validation)
- Calls render_report.py with appropriate flags
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_latest_audit_run(json_dir):
    """
    Scan json_dir for the most recent set of four audit JSONs.
    Returns a dict {benchmark_id -> path} or None if incomplete.
    """
    json_dir = Path(json_dir)
    if not json_dir.exists():
        return None

    # Expected benchmark IDs and their file patterns
    benchmarks = {
        "howtoharden": "howtoharden",
        "official-security": "official-security",
        "owasp-cicd": "owasp-cicd",
        "orphan-hygiene": "orphan-hygiene",
    }

    # Find all audit JSONs grouped by timestamp
    runs = {}  # timestamp -> {benchmark -> path}
    for json_file in json_dir.glob("jenkins-audit-*-*.json"):
        # Parse filename: jenkins-audit-{timestamp}-{benchmark}.json
        parts = json_file.name.replace(".json", "").split("-")
        if len(parts) < 5:  # jenkins, audit, {TS}, {TS}, {benchmark}...
            continue
        timestamp = f"{parts[2]}-{parts[3]}"  # YYYYMMDD-HHMMSS
        benchmark_part = "-".join(parts[4:])  # Handle multi-word benchmarks

        if timestamp not in runs:
            runs[timestamp] = {}
        runs[timestamp][benchmark_part] = json_file

    if not runs:
        return None

    # Find the most recent complete run
    for timestamp in sorted(runs.keys(), reverse=True):
        run = runs[timestamp]
        # Check if all four benchmarks present
        if all(b in run for b in benchmarks.values()):
            return {b: run[b] for b in benchmarks.values()}

    # If no complete run, return the most recent partial run
    latest_timestamp = sorted(runs.keys(), reverse=True)[0]
    return runs[latest_timestamp] if runs[latest_timestamp] else None


def check_completeness(files_dict):
    """
    Check if all four benchmark JSONs are present.
    Returns (is_complete: bool, found: list, missing: list)
    """
    expected = {"howtoharden", "official-security", "owasp-cicd", "orphan-hygiene"}
    found = set(files_dict.keys())
    missing = expected - found

    return len(missing) == 0, sorted(found), sorted(missing)


def prompt_incomplete(missing):
    """Prompt user if incomplete. Returns True if user wants to proceed."""
    print("\n⚠️  Incomplete audit report detected.")
    print(f"Missing sources: {', '.join(missing)}")
    print("\nRender incomplete report anyway? (y/n): ", end="", flush=True)

    response = input().strip().lower()
    return response in ("y", "yes")


def main():
    parser = argparse.ArgumentParser(
        description="Render Jenkins audit JSONs into HTML with smart defaults"
    )
    parser.add_argument(
        "json_paths",
        nargs="*",
        help="Path to JSON audit files (optional; auto-detects latest if not provided)",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip user prompt for incomplete reports; render anyway",
    )
    parser.add_argument(
        "--json-dir",
        default="reports",
        help="Directory to scan for latest audit JSONs (default: reports/)",
    )
    parser.add_argument(
        "--out",
        help="Output HTML file path (default: reports/jenkins-gen-report-<timestamp>.html)",
    )

    args = parser.parse_args()

    # Determine which JSONs to use
    if args.json_paths:
        # User provided explicit paths
        files_dict = {
            path.replace("jenkins-audit-", "").split("-", 1)[1].replace(".json", ""): path
            for path in args.json_paths
        }
        json_files = args.json_paths
    else:
        # Auto-detect latest run
        print("Scanning for latest audit run...")
        files_dict = find_latest_audit_run(args.json_dir)

        if not files_dict:
            print("Error: No audit JSONs found in reports/")
            sys.exit(1)

        json_files = [str(p) for p in files_dict.values()]
        print(f"Found audit from {list(files_dict.values())[0].parent.name}/")

    # Check completeness
    is_complete, found, missing = check_completeness(files_dict)

    if not is_complete:
        print(f"Found sources: {', '.join(found)}")
        print(f"Missing sources: {', '.join(missing)}")

        if not args.skip_validation:
            if not prompt_incomplete(missing):
                print("Aborting.")
                sys.exit(0)
        else:
            print("--skip-validation enabled; proceeding with incomplete data")

    # Determine output path
    if not args.out:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        args.out = f"reports/jenkins-gen-report-{timestamp}.html"

    # Call render_report.py
    render_script = Path(__file__).parent.parent / "jenkins-audit" / "render_report.py"

    if not render_script.exists():
        print(f"Error: render_report.py not found at {render_script}")
        sys.exit(1)

    cmd = ["python3", str(render_script)] + json_files + ["--out", args.out]

    if not is_complete:
        # Add a marker that report is incomplete (would need render_report.py to support this)
        # For now, just note it in output
        pass

    print(f"\nRendering report to {args.out}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error rendering report:\n{result.stderr}")
        sys.exit(1)

    print(result.stdout)

    # If incomplete, add warning to user
    if not is_complete:
        print(
            f"\n⚠️  Report is incomplete. Missing sources: {', '.join(missing)}"
        )
        print("Do not use this report for compliance decisions without all data.")

    print(f"\n✓ Report saved to: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
