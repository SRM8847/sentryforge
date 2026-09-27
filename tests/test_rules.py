#!/usr/bin/env python3
"""
test_rules.py — Feeds each fixture into wazuh-logtest and checks whether the
expected custom rule fired (or correctly did not), per tests/expectations.json.

Exit code 0 = all fixtures behaved as expected. Exit code 1 = at least one
mismatch, causing CI to fail before deploy ever runs.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
EXPECTATIONS_PATH = Path(__file__).parent / "expectations.json"
WAZUH_LOGTEST = "/var/ossec/bin/wazuh-logtest"

# Strips the archives.log-style prefix, e.g.:
# "2026 Sep 26 13:44:28 (soumya-3) any->/var/log/audit/audit.log type=SYSCALL ..."
# -> "type=SYSCALL ..."
ARCHIVE_PREFIX_RE = re.compile(r"^\d{4} \w+ \d+ [\d:]+ \([^)]*\) any->\S+ ")

RULE_ID_RE = re.compile(r"^\s*id:\s*'(\d+)'", re.MULTILINE)


def clean_line(line: str) -> str:
    return ARCHIVE_PREFIX_RE.sub("", line.rstrip("\n"))


def run_wazuh_logtest(lines):
    """Feed all lines into one wazuh-logtest session, return the set of rule
    IDs seen across the whole session's output."""
    stdin_data = "".join(f"{clean_line(l)}\n\n" for l in lines)
    result = subprocess.run(
        ["sudo", WAZUH_LOGTEST],
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=30,
    )
    # wazuh-logtest writes its actual decode/rule output to stderr when no
    # TTY is attached (confirmed empirically), not stdout.
    combined_output = result.stdout + result.stderr
    matched_ids = {int(m.group(1)) for m in RULE_ID_RE.finditer(combined_output)}
    return matched_ids, combined_output


def main():
    expectations = json.loads(EXPECTATIONS_PATH.read_text())
    failures = []

    for fixture_name, expectation in expectations.items():
        fixture_path = FIXTURES_DIR / fixture_name
        if not fixture_path.exists():
            failures.append(f"{fixture_name}: fixture file not found")
            continue

        lines = fixture_path.read_text().splitlines()
        matched_ids, raw_output = run_wazuh_logtest(lines)

        rule_id = expectation["rule_id"]
        should_fire = expectation["should_fire"]
        did_fire = rule_id in matched_ids

        if did_fire == should_fire:
            status = "PASS"
        else:
            status = "FAIL"
            failures.append(
                f"{fixture_name}: expected rule {rule_id} "
                f"{'to fire' if should_fire else 'NOT to fire'}, "
                f"but it {'did' if did_fire else 'did not'}. "
                f"Matched rule IDs this session: {sorted(matched_ids)}"
            )

        print(f"[{status}] {fixture_name} (rule {rule_id}, expect fire={should_fire})")

    print()
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print(f"All {len(expectations)} fixture checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
