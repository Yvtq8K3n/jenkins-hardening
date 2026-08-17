#!/usr/bin/env python3
"""Render JSON audit findings into a self-contained HTML report."""

import argparse
import json
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path


def load_benchmarks(paths):
    """Parse and validate JSON benchmark files. Exit non-zero on error."""
    benchmarks = []
    for path_str in paths:
        path = Path(path_str)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: {path} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)

        # Minimal schema validation
        required_keys = {"schema_version", "benchmark", "audit", "summary", "controls"}
        if not required_keys.issubset(data.keys()):
            print(
                f"Error: {path} missing required keys: {required_keys - set(data.keys())}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Validate controls
        for control in data["controls"]:
            if control["status"] not in ("PASS", "FAIL", "MANUAL", "LACK PRIVS"):
                print(
                    f"Error: {path} control {control['id']} has invalid status: {control['status']}",
                    file=sys.stderr,
                )
                sys.exit(1)

        benchmarks.append(data)

    return benchmarks


def recompute_summary(benchmark):
    """Derive summary from controls. Warn if it disagrees with agent-reported summary."""
    controls = benchmark["controls"]
    derived = {
        "pass": sum(1 for c in controls if c["status"] == "PASS"),
        "fail": sum(1 for c in controls if c["status"] == "FAIL"),
        "manual": sum(1 for c in controls if c["status"] == "MANUAL"),
        "lack_privs": sum(1 for c in controls if c["status"] == "LACK PRIVS"),
        "total": len(controls),
    }

    reported = benchmark["summary"]
    if derived != reported:
        print(
            f"Warning: {benchmark['benchmark']['id']} summary mismatch. "
            f"Derived: {derived}, Reported: {reported}. Using derived.",
            file=sys.stderr,
        )

    return derived


def build_unified_checklist(benchmarks):
    """Flatten all controls across benchmarks, preserving original order within each benchmark."""
    all_controls = []
    for b in benchmarks:
        for c in b["controls"]:
            all_controls.append({
                "id": c["id"],
                "benchmark": b["benchmark"]["id"],
                "title": c["title"],
                "status": c["status"],
            })
    # Keep original order — don't sort by status
    return all_controls


def build_remediation_roadmap(benchmarks):
    """Split controls into FAIL, LACK PRIVS, MANUAL, grouped by benchmark."""
    fail_rows = []
    lack_privs_rows = []
    manual_rows = []

    for b in benchmarks:
        bid = b["benchmark"]["id"]
        for c in b["controls"]:
            row = {
                "id": c["id"],
                "benchmark": bid,
                "title": c["title"],
                "evidence": c["evidence"],
                "remediation": c["remediation"],
                "reason": c.get("reason", None),  # Track reason if present
            }
            if c["status"] == "FAIL":
                fail_rows.append(row)
            elif c["status"] == "LACK PRIVS":
                lack_privs_rows.append(row)
            elif c["status"] == "MANUAL":
                manual_rows.append(row)

    return fail_rows, lack_privs_rows, manual_rows


def overall_status(totals):
    """Derive overall status: CRITICAL if any FAIL, NEEDS REVIEW if any MANUAL/LACK PRIVS, else PASS."""
    if totals["fail"] > 0:
        return "CRITICAL"
    elif totals["manual"] > 0 or totals.get("lack_privs", 0) > 0:
        return "NEEDS REVIEW"
    else:
        return "PASS"


def render_pie_chart_svg(pass_count, fail_count, manual_count, lack_privs_count=0, size=120):
    """Render a pie chart as inline SVG. Returns SVG string."""
    total = pass_count + fail_count + manual_count + lack_privs_count
    if total == 0:
        return ""

    # Colors
    colors = {"PASS": "#0ca30c", "FAIL": "#d03b3b", "MANUAL": "#fab219", "LACK PRIVS": "#9b7ccf"}

    # Calculate percentages and angles
    pass_pct = (pass_count / total) * 100 if total > 0 else 0
    fail_pct = (fail_count / total) * 100 if total > 0 else 0
    manual_pct = (manual_count / total) * 100 if total > 0 else 0
    lack_privs_pct = (lack_privs_count / total) * 100 if total > 0 else 0

    # Convert to angles (0-360)
    pass_angle = (pass_pct / 100) * 360
    fail_angle = (fail_pct / 100) * 360
    manual_angle = (manual_pct / 100) * 360
    lack_privs_angle = (lack_privs_pct / 100) * 360

    radius = size / 2
    center = radius

    def angle_to_coords(angle, r):
        """Convert angle (degrees) to SVG coordinates."""
        import math
        rad = math.radians(angle)
        return (center + r * math.cos(rad), center + r * math.sin(rad))

    def svg_arc(start_angle, end_angle, color):
        """Generate SVG path for pie slice."""
        import math
        if end_angle - start_angle >= 360:
            return None

        start_rad = math.radians(start_angle - 90)
        end_rad = math.radians(end_angle - 90)

        x1 = center + radius * math.cos(start_rad)
        y1 = center + radius * math.sin(start_rad)
        x2 = center + radius * math.cos(end_rad)
        y2 = center + radius * math.sin(end_rad)

        large_arc = 1 if (end_angle - start_angle) > 180 else 0

        path = f"M {center} {center} L {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2} Z"
        return f'<path d="{path}" fill="{color}" stroke="var(--surface-color, #fcfcfb)" stroke-width="2" />'

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" style="width: {size}px; height: {size}px;">']

    # Draw slices in order: FAIL, LACK PRIVS, MANUAL, PASS
    current_angle = 0

    if fail_count > 0:
        path = svg_arc(current_angle, current_angle + fail_angle, colors["FAIL"])
        if path:
            svg.append(path)
        current_angle += fail_angle

    if lack_privs_count > 0:
        path = svg_arc(current_angle, current_angle + lack_privs_angle, colors["LACK PRIVS"])
        if path:
            svg.append(path)
        current_angle += lack_privs_angle

    if manual_count > 0:
        path = svg_arc(current_angle, current_angle + manual_angle, colors["MANUAL"])
        if path:
            svg.append(path)
        current_angle += manual_angle

    if pass_count > 0:
        path = svg_arc(current_angle, current_angle + pass_angle, colors["PASS"])
        if path:
            svg.append(path)

    svg.append("</svg>")
    return "\n".join(svg)


def render_pie_with_legend_html(pass_count, fail_count, manual_count, lack_privs_count=0, title=""):
    """Render a pie chart with legend as HTML."""
    total = pass_count + fail_count + manual_count + lack_privs_count
    if total == 0:
        return ""

    pie_svg = render_pie_chart_svg(pass_count, fail_count, manual_count, lack_privs_count, size=100)

    html = f'''<div style="display: flex; align-items: center; gap: 20px; margin: 15px 0;">
      <div style="flex-shrink: 0;">
        {pie_svg}
      </div>
      <div style="font-size: 13px;">
        <div style="margin-bottom: 8px;"><strong style="color: var(--ink-primary);">{title}</strong></div>
        <div style="margin-bottom: 4px;"><span style="display: inline-block; width: 12px; height: 12px; background: #d03b3b; border-radius: 2px; margin-right: 6px;"></span>FAIL: {fail_count}</div>
        <div style="margin-bottom: 4px;"><span style="display: inline-block; width: 12px; height: 12px; background: #9b7ccf; border-radius: 2px; margin-right: 6px;"></span>LACK PRIVS: {lack_privs_count}</div>
        <div style="margin-bottom: 4px;"><span style="display: inline-block; width: 12px; height: 12px; background: #fab219; border-radius: 2px; margin-right: 6px;"></span>MANUAL: {manual_count}</div>
        <div><span style="display: inline-block; width: 12px; height: 12px; background: #0ca30c; border-radius: 2px; margin-right: 6px;"></span>PASS: {pass_count}</div>
      </div>
    </div>'''

    return html


def render_stacked_bar_svg(benchmarks, width=600, height=60, gap=8):
    """Render a horizontal 100%-stacked bar chart as inline SVG. Returns SVG string."""
    # Compute grand totals
    grand_totals = {"PASS": 0, "FAIL": 0, "MANUAL": 0, "LACK PRIVS": 0}
    for b in benchmarks:
        summary = recompute_summary(b)
        grand_totals["PASS"] += summary["pass"]
        grand_totals["FAIL"] += summary["fail"]
        grand_totals["MANUAL"] += summary["manual"]
        grand_totals["LACK PRIVS"] += summary["lack_privs"]

    grand_total = sum(grand_totals.values())

    # Colors (from dataviz validated palette)
    colors = {"PASS": "#0ca30c", "FAIL": "#d03b3b", "MANUAL": "#fab219", "LACK PRIVS": "#9b7ccf"}

    rows = [
        {"label": "Total", "summary": grand_totals, "total": grand_total},
    ]
    for b in benchmarks:
        summary = recompute_summary(b)
        total = summary["total"]
        rows.append({
            "label": b["benchmark"]["id"],
            "summary": {"PASS": summary["pass"], "FAIL": summary["fail"], "MANUAL": summary["manual"], "LACK PRIVS": summary["lack_privs"]},
            "total": total,
        })

    # SVG header
    svg_height = len(rows) * (height + gap)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {svg_height}" style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif; font-size: 12px;">']

    # Render each bar
    y_offset = 0
    for row in rows:
        total = row["total"]
        if total == 0:
            y_offset += height + gap
            continue

        x = 80  # Leave room for label
        for status in ("FAIL", "LACK PRIVS", "MANUAL", "PASS"):
            count = row["summary"][status]
            if count == 0:
                continue

            bar_width = (count / total) * (width - 100)
            svg.append(
                f'<rect x="{x}" y="{y_offset}" width="{bar_width}" height="{height}" '
                f'fill="{colors[status]}" stroke="var(--surface-color, #fcfcfb)" stroke-width="2" rx="4" />'
            )

            # Label inside the segment if wide enough
            if bar_width > 40:
                text_x = x + bar_width / 2
                text_y = y_offset + height / 2 + 4
                text_color = "#ffffff" if status in ("FAIL", "LACK PRIVS", "PASS") else "#0b0b0b"
                svg.append(
                    f'<text x="{text_x}" y="{text_y}" text-anchor="middle" fill="{text_color}" '
                    f'font-weight="600" font-size="11">{count}</text>'
                )

            x += bar_width + 2

        # Row label
        svg.append(
            f'<text x="5" y="{y_offset + height / 2 + 4}" text-anchor="start" '
            f'fill="var(--ink-primary, #0b0b0b)" font-size="12" font-weight="500">{escape(row["label"])}</text>'
        )

        y_offset += height + gap

    svg.append("</svg>")
    return "\n".join(svg)


def render_html(benchmarks, totals):
    """Render the complete HTML report."""
    unified_checklist = build_unified_checklist(benchmarks)
    fail_rows, lack_privs_rows, manual_rows = build_remediation_roadmap(benchmarks)
    status = overall_status(totals)

    # Gather metadata
    first_audit = benchmarks[0]["audit"]
    target_url = escape(first_audit["target_url"])
    audit_user = escape(first_audit.get("audit_user", "unknown") or "unknown")
    generated_at = first_audit["generated_at"]

    # Build benchmarks list for header
    def format_benchmark_link(b):
        # Orphan-hygiene uses custom rules, don't link to non-existent source
        if b["benchmark"]["id"] == "orphan-hygiene":
            return f'{escape(b["benchmark"]["name"])} <em>(Custom Rules)</em>'
        else:
            return f'<a href="{escape(b["benchmark"]["source_url"])}">{escape(b["benchmark"]["name"])}</a>'

    benchmarks_list = ", ".join(format_benchmark_link(b) for b in benchmarks)

    # SVG chart
    chart_svg = render_stacked_bar_svg(benchmarks)

    # Status badge color
    badge_color = "#d03b3b" if status == "CRITICAL" else "#fab219" if status == "NEEDS REVIEW" else "#0ca30c"
    badge_text = "white" if status in ("CRITICAL", "PASS") else "#0b0b0b"

    html_parts = []
    html_parts.append(r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Jenkins Hardening Audit Report</title>
  <style>
    :root {
      --surface-color: #fcfcfb;
      --page-bg: #f9f9f7;
      --ink-primary: #0b0b0b;
      --ink-secondary: #52514e;
      --ink-muted: #898781;
      --accent-pass: #0ca30c;
      --accent-fail: #d03b3b;
      --accent-manual: #fab219;
      --border-color: #e5e5e0;
      --code-bg: #f1f1f0;
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --surface-color: #1a1a19;
        --page-bg: #0d0d0c;
        --ink-primary: #ffffff;
        --ink-secondary: #c3c2b7;
        --ink-muted: #52514e;
        --border-color: #2d2d2c;
        --code-bg: #23231f;
      }
    }

    * {
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--page-bg);
      color: var(--ink-primary);
      line-height: 1.6;
      margin: 0;
      padding: 20px;
    }

    .container {
      max-width: 1000px;
      margin: 0 auto;
    }

    header {
      border-bottom: 2px solid var(--border-color);
      padding-bottom: 20px;
      margin-bottom: 30px;
    }

    h1 {
      font-size: 28px;
      font-weight: 600;
      margin: 0 0 10px 0;
      line-height: 1.2;
    }

    h2 {
      font-size: 20px;
      font-weight: 600;
      margin: 30px 0 15px 0;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 8px;
    }

    h3 {
      font-size: 16px;
      font-weight: 600;
      margin: 20px 0 10px 0;
    }

    .metadata {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 15px;
      margin-top: 15px;
      font-size: 14px;
    }

    .metadata-item {
      background: var(--surface-color);
      padding: 10px 12px;
      border-radius: 4px;
      border-left: 3px solid var(--accent-manual);
    }

    .metadata-label {
      font-weight: 600;
      color: var(--ink-secondary);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }

    .metadata-value {
      color: var(--ink-primary);
      word-break: break-all;
    }

    .executive-summary {
      background: var(--surface-color);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 20px;
      margin-bottom: 30px;
    }

    .stat-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }

    .stat-tile {
      text-align: center;
      padding: 12px;
      background: var(--page-bg);
      border-radius: 4px;
      border-left: 3px solid var(--accent-manual);
    }

    .stat-tile.fail {
      border-left-color: var(--accent-fail);
    }

    .stat-tile.manual {
      border-left-color: var(--accent-manual);
    }

    .stat-tile.pass {
      border-left-color: var(--accent-pass);
    }

    .stat-number {
      font-size: 24px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }

    .stat-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--ink-secondary);
      margin-top: 4px;
    }

    .chart-container {
      margin: 20px 0;
      overflow-x: auto;
    }

    .badge {
      display: inline-block;
      padding: 6px 12px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 14px;
      margin-top: 10px;
    }

    .badge.critical {
      background: var(--accent-fail);
      color: white;
    }

    .badge.needs-review {
      background: var(--accent-manual);
      color: #0b0b0b;
    }

    .badge.pass {
      background: var(--accent-pass);
      color: white;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
      background: var(--surface-color);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      overflow: hidden;
    }

    th {
      background: var(--page-bg);
      padding: 12px;
      text-align: left;
      font-weight: 600;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--ink-secondary);
      border-bottom: 1px solid var(--border-color);
    }

    td {
      padding: 12px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    tr:last-child td {
      border-bottom: none;
    }

    .status-pass {
      background: var(--accent-pass);
      color: white;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 12px;
      font-weight: 600;
      text-align: center;
      display: inline-block;
    }

    .status-fail {
      background: var(--accent-fail);
      color: white;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 12px;
      font-weight: 600;
      text-align: center;
      display: inline-block;
    }

    .status-manual {
      background: var(--accent-manual);
      color: #0b0b0b;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 12px;
      font-weight: 600;
      text-align: center;
      display: inline-block;
    }

    .status-lack\ privs {
      background: #9b7ccf;
      color: white;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 12px;
      font-weight: 600;
      text-align: center;
      display: inline-block;
    }

    details {
      background: var(--surface-color);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 0;
      margin-bottom: 12px;
    }

    summary {
      padding: 12px;
      cursor: pointer;
      font-weight: 600;
      user-select: none;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    summary:hover {
      background: var(--page-bg);
    }

    details[open] > summary {
      border-bottom: 1px solid var(--border-color);
    }

    .details-content {
      padding: 12px;
    }

    .remediation-section {
      background: var(--surface-color);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 15px;
      margin-bottom: 15px;
    }

    .remediation-section h4 {
      margin: 0 0 10px 0;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--ink-secondary);
    }

    .control-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    .control-list li {
      padding: 8px 0;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    .control-list li:last-child {
      border-bottom: none;
    }

    .control-id {
      font-weight: 600;
      color: var(--ink-secondary);
    }

    footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--border-color);
      font-size: 13px;
      color: var(--ink-secondary);
    }

    a {
      color: var(--ink-primary);
      text-decoration: underline;
    }

    code {
      background: var(--code-bg);
      padding: 2px 4px;
      border-radius: 2px;
      font-family: "SF Mono", Monaco, Menlo, Courier, monospace;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
""")

    # Header
    html_parts.append(f"""    <header>
      <h1>Jenkins Hardening Audit Report</h1>
      <div class="metadata">
        <div class="metadata-item">
          <div class="metadata-label">Target URL</div>
          <div class="metadata-value"><code>{target_url}</code></div>
        </div>
        <div class="metadata-item">
          <div class="metadata-label">Audit User</div>
          <div class="metadata-value">{audit_user}</div>
        </div>
        <div class="metadata-item">
          <div class="metadata-label">Generated At (UTC)</div>
          <div class="metadata-value">{escape(generated_at)}</div>
        </div>
        <div class="metadata-item">
          <div class="metadata-label">Benchmarks</div>
          <div class="metadata-value">{benchmarks_list}</div>
        </div>
      </div>
    </header>
""")

    # Executive Summary
    html_parts.append(f"""    <section class="executive-summary">
      <h2>Executive Summary</h2>
      <div class="stat-row">
        <div class="stat-tile">
          <div class="stat-number" style="font-variant-numeric: tabular-nums;">{totals['total']}</div>
          <div class="stat-label">Total Controls</div>
        </div>
        <div class="stat-tile fail">
          <div class="stat-number" style="color: var(--accent-fail); font-variant-numeric: tabular-nums;">{totals['fail']}</div>
          <div class="stat-label">FAIL</div>
        </div>
        <div class="stat-tile manual">
          <div class="stat-number" style="color: #9b7ccf; font-variant-numeric: tabular-nums;">{totals.get('lack_privs', 0)}</div>
          <div class="stat-label">LACK PRIVS</div>
        </div>
        <div class="stat-tile manual">
          <div class="stat-number" style="color: var(--accent-manual); font-variant-numeric: tabular-nums;">{totals['manual']}</div>
          <div class="stat-label">MANUAL</div>
        </div>
        <div class="stat-tile pass">
          <div class="stat-number" style="color: var(--accent-pass); font-variant-numeric: tabular-nums;">{totals['pass']}</div>
          <div class="stat-label">PASS</div>
        </div>
      </div>
      <div class="chart-container">
        {chart_svg}
      </div>
      <h3 style="margin-top: 30px; margin-bottom: 20px;">Breakdown by Benchmark</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 20px;">
""")

    # Add pie charts for each benchmark
    for b in benchmarks:
        summary = recompute_summary(b)
        pie_html = render_pie_with_legend_html(
            summary["pass"],
            summary["fail"],
            summary["manual"],
            summary["lack_privs"],
            title=escape(b["benchmark"]["name"])
        )
        html_parts.append(f"""        <div>
          {pie_html}
        </div>
""")

    html_parts.append("""      </div>
      <div>
        <div class="badge" style="background: {badge_color}; color: {badge_text};">Status: {status}</div>
      </div>
    </section>
""".format(badge_color=badge_color, badge_text=badge_text, status=status))

    # Unified Checklist
    html_parts.append("""    <section>
      <h2>Unified Control Checklist</h2>
      <table>
        <thead>
          <tr>
            <th>Control ID</th>
            <th>Benchmark</th>
            <th>Title</th>
            <th style="text-align: center;">Status</th>
          </tr>
        </thead>
        <tbody>
""")

    for row in unified_checklist:
        status_class = f"status-{row['status'].lower()}"
        html_parts.append(f"""          <tr>
            <td><code>{escape(row['id'])}</code></td>
            <td>{escape(row['benchmark'])}</td>
            <td>{escape(row['title'])}</td>
            <td style="text-align: center;"><span class="{status_class}">{row['status']}</span></td>
          </tr>
""")

    html_parts.append("""        </tbody>
      </table>
    </section>
""")

    # Detailed Findings by Benchmark
    html_parts.append("""    <section>
      <h2>Detailed Findings by Benchmark</h2>
""")

    for b in benchmarks:
        benchmark_id = escape(b["benchmark"]["id"])
        controls = b["controls"]

        html_parts.append(f"""      <h3>{escape(b['benchmark']['name'])}</h3>
""")

        for status in ("FAIL", "LACK PRIVS", "MANUAL", "PASS"):
            status_controls = [c for c in controls if c["status"] == status]
            if not status_controls:
                continue

            status_lower = status.lower().replace(" ", "-")
            status_class = f"status-{status_lower}"

            html_parts.append(f"""      <details>
        <summary>
          <span>{status} ({len(status_controls)})</span>
          <span style="font-size: 12px; color: var(--ink-secondary);">Click to expand</span>
        </summary>
        <div class="details-content">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Evidence</th>
                <th>Remediation</th>
              </tr>
            </thead>
            <tbody>
""")

            for c in status_controls:
                html_parts.append(f"""              <tr>
                <td><code>{escape(c['id'])}</code></td>
                <td>{escape(c['title'])}</td>
                <td>{escape(c['evidence'])}</td>
                <td>{escape(c['remediation'])}</td>
              </tr>
""")

            html_parts.append("""            </tbody>
          </table>
        </div>
      </details>
""")

    html_parts.append("    </section>\n")

    # Prioritized Remediation Roadmap
    html_parts.append("""    <section>
      <h2>Prioritized Remediation Roadmap</h2>
""")

    if fail_rows:
        html_parts.append("""      <div class="remediation-section">
        <h4>🔴 FAIL — Remediate Immediately</h4>
        <ul class="control-list">
""")
        fail_by_benchmark = {}
        for row in fail_rows:
            bid = row["benchmark"]
            if bid not in fail_by_benchmark:
                fail_by_benchmark[bid] = []
            fail_by_benchmark[bid].append(row)

        for bid, rows in sorted(fail_by_benchmark.items()):
            for row in rows:
                html_parts.append(f"""          <li><span class="control-id">{escape(row['id'])}</span> — {escape(row['title'])}<br/><strong>Fix:</strong> {escape(row['remediation'])}</li>
""")

        html_parts.append("""        </ul>
      </div>
""")

    if lack_privs_rows:
        html_parts.append("""      <div class="remediation-section" style="border-left: 4px solid #9b7ccf;">
        <h4>🔐 LACK PRIVS — Re-run with Admin Credentials</h4>
        <p style="font-size: 13px; margin-bottom: 12px; color: var(--ink-secondary);">
          These controls could not be evaluated because the audit token lacks sufficient permissions (e.g., Overall/Administer or PluginManager access).
          Re-run the audit with an admin token to get definitive PASS/FAIL verdicts on these controls.
        </p>
        <ul class="control-list">
""")
        lack_privs_by_benchmark = {}
        for row in lack_privs_rows:
            bid = row["benchmark"]
            if bid not in lack_privs_by_benchmark:
                lack_privs_by_benchmark[bid] = []
            lack_privs_by_benchmark[bid].append(row)

        for bid, rows in sorted(lack_privs_by_benchmark.items()):
            for row in rows:
                html_parts.append(f"""          <li><span class="control-id">{escape(row['id'])}</span> — {escape(row['title'])}<br/><strong>Evidence:</strong> {escape(row['evidence'])}</li>
""")

        html_parts.append("""        </ul>
      </div>
""")

    if manual_rows:
        html_parts.append("""      <div class="remediation-section">
        <h4>📋 MANUAL — Requires Human Review</h4>
        <ul class="control-list">
""")
        manual_by_benchmark = {}
        for row in manual_rows:
            bid = row["benchmark"]
            if bid not in manual_by_benchmark:
                manual_by_benchmark[bid] = []
            manual_by_benchmark[bid].append(row)

        for bid, rows in sorted(manual_by_benchmark.items()):
            for row in rows:
                html_parts.append(f"""          <li><span class="control-id">{escape(row['id'])}</span> — {escape(row['title'])}<br/><strong>Evidence:</strong> {escape(row['evidence'])}</li>
""")

        html_parts.append("""        </ul>
      </div>
""")

    html_parts.append("    </section>\n")

    # Methodology Footer
    html_parts.append("""    <footer>
      <h3>Audit Methodology</h3>
      <p>This report was generated by auditing a Jenkins instance against four independent security benchmarks and operational hygiene rulesets:</p>
      <ul>
""")

    for b in benchmarks:
        if b["benchmark"]["id"] == "orphan-hygiene":
            html_parts.append(
                f"""        <li><strong>{escape(b['benchmark']['name'])}</strong> — Custom operational hygiene ruleset (see checklist for sources: CIS, OWASP, Jenkins.io, team best practices)</li>
"""
            )
        else:
            html_parts.append(
                f"""        <li><strong>{escape(b['benchmark']['name'])}</strong> — <a href="{escape(b['benchmark']['source_url'])}">{escape(b['benchmark']['source_url'])}</a></li>
"""
            )

    html_parts.append(f"""      </ul>
      <p><strong>Schema Version:</strong> {escape(benchmarks[0]['schema_version'])}</p>
      <p><strong>Report Generated:</strong> {escape(generated_at)} (UTC)</p>
    </footer>
  </div>
</body>
</html>
""")

    return "".join(html_parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "json_files",
        nargs="+",
        help="JSON benchmark files to combine",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output HTML file path",
    )
    args = parser.parse_args()

    benchmarks = load_benchmarks(args.json_files)

    # Compute grand totals
    grand_totals = {"pass": 0, "fail": 0, "manual": 0, "lack_privs": 0, "total": 0}
    for b in benchmarks:
        summary = recompute_summary(b)
        grand_totals["pass"] += summary["pass"]
        grand_totals["fail"] += summary["fail"]
        grand_totals["manual"] += summary["manual"]
        grand_totals["lack_privs"] += summary["lack_privs"]
        grand_totals["total"] += summary["total"]

    html = render_html(benchmarks, grand_totals)

    output_path = Path(args.out)
    output_path.write_text(html, encoding="utf-8")

    print(output_path.absolute())


if __name__ == "__main__":
    main()
