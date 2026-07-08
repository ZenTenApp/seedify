#!/usr/bin/env python3
"""Parse the per-day `seedify --full` outputs collected by run-sweep.sh into
structured sections, then diff them against a baseline day and against each
day's predecessor.

seedify's `--full` output (with color disabled, as run-sweep.sh does) is a
sequence of `-----BEGIN X-----` / `-----END X-----` PEM-style blocks (the SSH
key preamble) followed by `[section title]` headers introducing mnemonics and
derived addresses (see cmd/seedify/output.go: Section/Sectionf/SeedSection/
AddressSection). This script treats everything before the first `[...]`
header as a single "preamble" section, and every subsequent `[...]` header as
the start of a new named section running until the next header.

Outputs (written to --results-dir):
  parsed/YYYY-MM-DD.json  section name -> body text, for one day
  summary.json            section name -> sha256 body hash, for every day
  diffs.json              which sections changed vs baseline / vs previous day
  report.md               human-readable summary of the above
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

SECTION_HEADER_RE = re.compile(r"^\[(.+)\]$")
PREAMBLE_KEY = "preamble"


def parse_sections(raw_text: str) -> dict[str, str]:
    """Splits raw seedify output into {section_name: body_text}."""
    sections: dict[str, list[str]] = {PREAMBLE_KEY: []}
    current = PREAMBLE_KEY
    for line in raw_text.splitlines():
        match = SECTION_HEADER_RE.match(line.strip())
        if match:
            current = match.group(1).strip()
            sections.setdefault(current, [])
            continue
        sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items() if "\n".join(lines).strip()}


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_all_days(raw_dir: Path) -> dict[str, dict[str, str]]:
    days: dict[str, dict[str, str]] = {}
    for raw_file in sorted(raw_dir.glob("*.txt")):
        date_str = raw_file.stem
        days[date_str] = parse_sections(raw_file.read_text())
    return days


def build_summary(days: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {
        date_str: {name: sha256_of(body) for name, body in sections.items()}
        for date_str, sections in days.items()
    }


def build_diffs(summary: dict[str, dict[str, str]]) -> dict:
    dates = sorted(summary.keys())
    if not dates:
        return {"baseline": None, "vs_baseline": {}, "vs_previous_day": {}, "sections_ever_changed": {}}

    baseline_date = dates[0]
    baseline_hashes = summary[baseline_date]

    vs_baseline: dict[str, list[str]] = {}
    vs_previous_day: dict[str, list[str]] = {}
    ever_changed: dict[str, int] = {}

    previous_hashes = baseline_hashes
    for date_str in dates:
        hashes = summary[date_str]
        all_sections = set(hashes) | set(baseline_hashes)

        changed_vs_baseline = sorted(
            name for name in all_sections if hashes.get(name) != baseline_hashes.get(name)
        )
        if changed_vs_baseline:
            vs_baseline[date_str] = changed_vs_baseline
            for name in changed_vs_baseline:
                ever_changed[name] = ever_changed.get(name, 0) + 1

        if date_str != baseline_date:
            all_prev_sections = set(hashes) | set(previous_hashes)
            changed_vs_previous = sorted(
                name for name in all_prev_sections if hashes.get(name) != previous_hashes.get(name)
            )
            if changed_vs_previous:
                vs_previous_day[date_str] = changed_vs_previous

        previous_hashes = hashes

    return {
        "baseline": baseline_date,
        "vs_baseline": vs_baseline,
        "vs_previous_day": vs_previous_day,
        "sections_ever_changed": dict(sorted(ever_changed.items())),
    }


def write_report_md(path: Path, year: str, summary: dict, diffs: dict) -> None:
    dates = sorted(summary.keys())
    lines = [f"# Seedify {year} Date-Sweep Report", ""]
    lines.append(f"Days collected: {len(dates)}")
    lines.append(f"Baseline date: {diffs.get('baseline')}")
    lines.append("")

    ever_changed = diffs.get("sections_ever_changed", {})
    if not ever_changed:
        lines.append("No section ever differed from the baseline across the sweep.")
    else:
        lines.append("## Sections that changed at least once vs baseline")
        lines.append("")
        lines.append("| Section | Days differing from baseline |")
        lines.append("|---|---|")
        for name, count in sorted(ever_changed.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {name} | {count} / {len(dates)} |")
        lines.append("")

    all_section_names = {name for hashes in summary.values() for name in hashes}
    stable_sections = sorted(all_section_names - set(ever_changed))
    if stable_sections:
        lines.append("## Sections that never changed")
        lines.append("")
        for name in stable_sections:
            lines.append(f"- {name}")
        lines.append("")

    vs_previous_day = diffs.get("vs_previous_day", {})
    lines.append(f"## Days where output differed from the previous day: {len(vs_previous_day)} / {max(len(dates) - 1, 0)}")
    if vs_previous_day:
        lines.append("")
        first_five = list(vs_previous_day.items())[:5]
        lines.append("First few day-to-day changes:")
        lines.append("")
        for date_str, changed in first_five:
            lines.append(f"- {date_str}: {', '.join(changed)}")

    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--year", required=True)
    args = parser.parse_args()

    results_dir: Path = args.results_dir
    raw_dir = results_dir / "raw"
    parsed_dir = results_dir / "parsed"
    parsed_dir.mkdir(parents=True, exist_ok=True)

    days = load_all_days(raw_dir)
    for date_str, sections in days.items():
        (parsed_dir / f"{date_str}.json").write_text(json.dumps(sections, indent=2, sort_keys=True))

    summary = build_summary(days)
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))

    diffs = build_diffs(summary)
    (results_dir / "diffs.json").write_text(json.dumps(diffs, indent=2, sort_keys=True))

    write_report_md(results_dir / "report.md", args.year, summary, diffs)


if __name__ == "__main__":
    main()
