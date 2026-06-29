#!/usr/bin/env python3
"""
Linux Security Analyzer

Reads recent SSH/authentication-related logs from journalctl and produces:
- a security summary
- a risk score
- a Markdown report
- an optional HTML report
"""

from __future__ import annotations

import argparse
import html
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


FAILED_PATTERNS = [
    re.compile(r"Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>\S+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"),
]

SUDO_PATTERN = re.compile(r"sudo:.*COMMAND=(?P<cmd>.+)$")
USER_MGMT_PATTERN = re.compile(r"\b(useradd|adduser|usermod|userdel|groupadd|groupdel|groupmod)\b")


@dataclass
class Summary:
    failed_logins: int
    successful_logins: int
    sudo_events: int
    user_mgmt_events: int
    top_failed_ips: List[Tuple[str, int]]
    risk_score: int
    severity: str
    recommendations: List[str]


def run_journalctl(since: str) -> List[str]:
    cmd = ["journalctl", "-u", "ssh", "--since", since, "--no-pager", "--output=short"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(
            "Failed to read journal logs. Try running with sudo:\n"
            "sudo python3 scripts/linux_security_analyzer.py"
        )

    return result.stdout.splitlines()


def analyze_lines(lines: List[str]) -> Summary:
    failed_count = 0
    success_count = 0
    sudo_count = 0
    user_mgmt_count = 0
    failed_ips: Counter[str] = Counter()

    for line in lines:
        matched_failed = False
        for pattern in FAILED_PATTERNS:
            match = pattern.search(line)
            if match:
                failed_count += 1
                ip = match.groupdict().get("ip")
                if ip:
                    failed_ips[ip] += 1
                matched_failed = True
                break

        for pattern in SUCCESS_PATTERNS:
            if pattern.search(line):
                success_count += 1
                break

        if SUDO_PATTERN.search(line):
            sudo_count += 1

        if USER_MGMT_PATTERN.search(line):
            user_mgmt_count += 1

    risk_score = 0
    risk_score += min(failed_count * 10, 50)
    risk_score += min(user_mgmt_count * 15, 30)
    risk_score += min(sudo_count * 5, 15)
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    recommendations = []
    if failed_count > 0:
        recommendations.append("Review failed authentication attempts for brute-force behavior.")
    if failed_ips:
        recommendations.append("Investigate the top source IP addresses generating failed logins.")
    if sudo_count > 0:
        recommendations.append("Review sudo activity for unexpected administrative changes.")
    if user_mgmt_count > 0:
        recommendations.append("Validate any user or group management actions.")
    if not recommendations:
        recommendations.append("No notable security events detected in the selected time window.")

    return Summary(
        failed_logins=failed_count,
        successful_logins=success_count,
        sudo_events=sudo_count,
        user_mgmt_events=user_mgmt_count,
        top_failed_ips=failed_ips.most_common(5),
        risk_score=risk_score,
        severity=severity,
        recommendations=recommendations,
    )


def build_markdown(summary: Summary, since: str) -> str:
    lines = [
        "# Linux Security Summary",
        "",
        f"**Time Window:** {since}",
        "",
        "## Risk Assessment",
        "",
        f"- **Risk Score:** {summary.risk_score}/100",
        f"- **Severity:** {summary.severity}",
        "",
        "## Metrics",
        "",
        f"- Failed SSH logins: {summary.failed_logins}",
        f"- Successful SSH logins: {summary.successful_logins}",
        f"- sudo events: {summary.sudo_events}",
        f"- User management events: {summary.user_mgmt_events}",
        "",
        "## Top Failed Login Sources",
        "",
    ]

    if summary.top_failed_ips:
        for ip, count in summary.top_failed_ips:
            lines.append(f"- {ip}: {count}")
    else:
        lines.append("- None detected")

    lines.extend(
        [
            "",
            "## Recommendations",
            "",
        ]
    )

    for rec in summary.recommendations:
        lines.append(f"- {rec}")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Review authentication logs for unusual spikes.",
            "- Correlate sudo usage with administrative activity.",
            "",
        ]
    )

    return "\n".join(lines)


def build_html(summary: Summary, since: str) -> str:
    top_ips_html = ""
    if summary.top_failed_ips:
        rows = "".join(
            f"<tr><td>{html.escape(ip)}</td><td>{count}</td></tr>"
            for ip, count in summary.top_failed_ips
        )
        top_ips_html = f"""
        <table>
            <tr><th>IP Address</th><th>Failed Attempts</th></tr>
            {rows}
        </table>
        """
    else:
        top_ips_html = "<p>None detected</p>"

    rec_items = "".join(f"<li>{html.escape(rec)}</li>" for rec in summary.recommendations)

    severity_class = summary.severity.lower()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Linux Security Summary</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f7f7f7;
            color: #111;
        }}
        .card {{
            background: white;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            max-width: 900px;
            margin: auto;
        }}
        h1, h2 {{
            margin-top: 0;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }}
        .metric {{
            background: #f0f0f0;
            padding: 16px;
            border-radius: 10px;
        }}
        .severity {{
            display: inline-block;
            padding: 8px 12px;
            border-radius: 999px;
            color: white;
            font-weight: bold;
            margin-left: 8px;
        }}
        .low {{ background: #2e7d32; }}
        .medium {{ background: #f9a825; }}
        .high {{ background: #c62828; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background: #fafafa;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Linux Security Summary</h1>
        <p><strong>Time Window:</strong> {html.escape(since)}</p>

        <p>
            <strong>Risk Score:</strong> {summary.risk_score}/100
            <span class="severity {severity_class}">{summary.severity}</span>
        </p>

        <div class="metric-grid">
            <div class="metric"><strong>Failed SSH Logins</strong><br>{summary.failed_logins}</div>
            <div class="metric"><strong>Successful SSH Logins</strong><br>{summary.successful_logins}</div>
            <div class="metric"><strong>sudo Events</strong><br>{summary.sudo_events}</div>
            <div class="metric"><strong>User Management Events</strong><br>{summary.user_mgmt_events}</div>
        </div>

        <h2>Top Failed Login Sources</h2>
        {top_ips_html}

        <h2>Recommendations</h2>
        <ul>
            {rec_items}
        </ul>
    </div>
</body>
</html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Linux SSH/auth logs and generate a security summary.")
    parser.add_argument("--since", default="24 hours ago", help='Time window for journalctl, e.g. "1 hour ago"')
    parser.add_argument("--md", action="store_true", help="Print Markdown report to stdout")
    parser.add_argument("--html", action="store_true", help="Write HTML report")
    parser.add_argument("--out", default="", help="Output path for Markdown report")
    parser.add_argument("--html-out", default="", help="Output path for HTML report")
    args = parser.parse_args()

    lines = run_journalctl(args.since)
    summary = analyze_lines(lines)

    print("=" * 50)
    print("LINUX SECURITY SUMMARY")
    print("=" * 50)
    print(f"Time window: {args.since}")
    print(f"Risk Score: {summary.risk_score}/100")
    print(f"Severity: {summary.severity}")
    print(f"Failed SSH logins: {summary.failed_logins}")
    print(f"Successful SSH logins: {summary.successful_logins}")
    print(f"sudo events: {summary.sudo_events}")
    print(f"User management events: {summary.user_mgmt_events}")
    print()

    if summary.top_failed_ips:
        print("Top failed login sources:")
        for ip, count in summary.top_failed_ips:
            print(f"  {ip}: {count}")
    else:
        print("Top failed login sources: none detected")

    print("\nRecommendations:")
    for rec in summary.recommendations:
        print(f"  - {rec}")

    if args.md or args.out:
        md = build_markdown(summary, args.since)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(md, encoding="utf-8")
            print(f"\nMarkdown report written to: {args.out}")
        else:
            print("\n" + md)

    if args.html or args.html_out:
        html_report = build_html(summary, args.since)
        out_path = args.html_out or "reports/linux-security-summary.html"
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(html_report, encoding="utf-8")
        print(f"\nHTML report written to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())#!/usr/bin/env python3
"""
Linux Security Log Analyzer

Collects recent SSH/authentication-related events from journalctl and prints a
simple security summary. Intended for Ubuntu Server labs.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


FAILED_PATTERNS = [
    re.compile(r"Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>\S+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"),
]

SUDO_PATTERN = re.compile(r"sudo:.*COMMAND=(?P<cmd>.+)$")
USERADD_PATTERN = re.compile(r"\b(useradd|adduser|usermod)\b")


@dataclass
class Summary:
    failed_logins: int
    successful_logins: int
    sudo_events: int
    user_mgmt_events: int
    top_failed_ips: List[Tuple[str, int]]


def run_journalctl(since: str) -> List[str]:
    """
    Pull recent SSH/authentication logs from systemd journal.
    """
    cmd = ["journalctl", "-u", "ssh", "--since", since, "--no-pager", "--output=short"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(
            "journalctl failed. Try running this script with sudo:\n"
            "sudo python3 scripts/linux_log_analyzer.py"
        )

    return result.stdout.splitlines()


def analyze_lines(lines: List[str]) -> Summary:
    failed_count = 0
    success_count = 0
    sudo_count = 0
    user_mgmt_count = 0
    failed_ips: Counter[str] = Counter()

    for line in lines:
        for pattern in FAILED_PATTERNS:
            match = pattern.search(line)
            if match:
                failed_count += 1
                ip = match.groupdict().get("ip")
                if ip:
                    failed_ips[ip] += 1
                break

        for pattern in SUCCESS_PATTERNS:
            if pattern.search(line):
                success_count += 1
                break

        if SUDO_PATTERN.search(line):
            sudo_count += 1

        if USERADD_PATTERN.search(line):
            user_mgmt_count += 1

    top_failed_ips = failed_ips.most_common(5)

    return Summary(
        failed_logins=failed_count,
        successful_logins=success_count,
        sudo_events=sudo_count,
        user_mgmt_events=user_mgmt_count,
        top_failed_ips=top_failed_ips,
    )


def build_markdown(summary: Summary, since: str) -> str:
    lines = [
        "# Linux Security Log Summary",
        "",
        f"**Time Window:** {since}",
        "",
        "## Metrics",
        "",
        f"- Failed SSH logins: {summary.failed_logins}",
        f"- Successful SSH logins: {summary.successful_logins}",
        f"- sudo events: {summary.sudo_events}",
        f"- User management events: {summary.user_mgmt_events}",
        "",
        "## Top Failed Login Sources",
        "",
    ]

    if summary.top_failed_ips:
        for ip, count in summary.top_failed_ips:
            lines.append(f"- {ip}: {count}")
    else:
        lines.append("- None detected")

    lines.extend(["", "## Notes", "", "- Review failed login spikes for brute-force behavior.", "- Correlate sudo activity with administrative changes.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze recent Linux security logs.")
    parser.add_argument(
        "--since",
        default="24 hours ago",
        help='Journal time window, e.g. "1 hour ago" or "24 hours ago"',
    )
    parser.add_argument(
        "--md",
        action="store_true",
        help="Also print a Markdown report",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Optional output file for Markdown report",
    )
    args = parser.parse_args()

    lines = run_journalctl(args.since)
    summary = analyze_lines(lines)

    print("=" * 50)
    print("LINUX SECURITY SUMMARY")
    print("=" * 50)
    print(f"Time window: {args.since}")
    print(f"Failed SSH logins: {summary.failed_logins}")
    print(f"Successful SSH logins: {summary.successful_logins}")
    print(f"sudo events: {summary.sudo_events}")
    print(f"User management events: {summary.user_mgmt_events}")
    print()

    if summary.top_failed_ips:
        print("Top failed login sources:")
        for ip, count in summary.top_failed_ips:
            print(f"  {ip}: {count}")
    else:
        print("Top failed login sources: none detected")

    if args.md or args.out:
        md = build_markdown(summary, args.since)
        if args.out:
            Path(args.out).write_text(md, encoding="utf-8")
            print(f"\nMarkdown report written to: {args.out}")
        else:
            print("\n" + md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
