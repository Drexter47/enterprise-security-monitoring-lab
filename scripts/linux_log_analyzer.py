#!/usr/bin/env python3
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
