"""report.py — JSON + Markdown report generation.

Aggregates engagements into reports/ as honeynet-<stamp>.json and
honeynet-<stamp>.md containing: engagements table, dwell stats, interaction
replay timeline, detected IOC list, and a recommendation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .logger import describe

REPORTS_DIR = "reports"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_reports_dir(path: str | None = None) -> Path:
    base = Path(path) if path else Path(REPORTS_DIR)
    base.mkdir(parents=True, exist_ok=True)
    return base


def recommender(scored: list[dict[str, Any]]) -> str:
    if not scored:
        return "No engagements captured. Continue monitoring."
    top = scored[0]
    src = top["src"]
    level = top["risk"]["level"]
    actions = top["actions"]
    if level in ("critical", "high"):
        return (
            f"Investigate {src}: {actions} actions observed (level={level}). "
            "Quarantine the source, sweep for planted honeytokens, rotate anything "
            "the fake creds would have reached, and review the replay timeline below."
        )
    if level == "medium":
        return f"Review {src}: {actions} actions (level=medium). Enrich with perimeter logs and alarm on re-attempts."
    return f"Low-risk contact from {src} ({actions} actions). Keep monitoring; no action required."


def replay_timeline(records: list[dict[str, Any]]) -> list[str]:
    return [describe(r) for r in sorted(records, key=lambda r: r["ts"])]


def build_report(
    records: list[dict[str, Any]],
    engagements: list[dict[str, Any]] | None = None,
    dwell_stats: dict[str, Any] | None = None,
    iocs: list[dict[str, str]] | None = None,
    recommendation: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scored = engagements or []
    return {
        "tool": "honeynet",
        "version": __version__,
        "generated": _stamp(),
        **(meta or {}),
        "engagements": scored,
        "stats": dwell_stats or {},
        "iocs": iocs or [],
        "replay": replay_timeline(records),
        "recommendation": recommendation or recommender(scored),
    }


def write_reports(
    report: dict[str, Any],
    out_dir: str | None = None,
    name: str = "honeynet-engagements",
) -> tuple[str, str]:
    base = ensure_reports_dir(out_dir)
    json_path = base / f"{name}-{_stamp()}.json"
    md_path = base / f"{name}-{_stamp()}.md"
    json_path.write_text(json.dumps(report, indent=2, default=str))
    md_path.write_text(to_markdown(report))
    return str(json_path), str(md_path)


def to_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# honeynet engagement report")
    lines.append("")
    lines.append(f"tool: {report.get('tool', 'honeynet')} v{report.get('version', '?')} · generated {report.get('generated', '?')}")
    lines.append("")
    if report.get("note"):
        lines.append(f"**note**: {report['note']}")
        lines.append("")

    stats = report.get("stats") or {}
    lines.append("## Dwell & Risk")
    lines.append("")
    if stats:
        lines.append("| metric | value |")
        lines.append("|---|---|")
        for key, val in sorted(stats.items()):
            lines.append(f"| {key} | {val} |")
    else:
        lines.append("_no statistics_")
    lines.append("")

    scored = report.get("engagements") or []
    lines.append("## Engagements")
    lines.append("")
    if scored:
        lines.append("| src | protocols | actions | dwell (s) | risk | flags |")
        lines.append("|---|---|---|---|---|---|")
        for e in scored:
            flags = ", ".join(e.get("flags", [])[:3]) or "-"
            lines.append(
                f"| {e['src']} | {', '.join(e.get('protocols', []))} | {e['actions']} "
                f"| {e['dwell_seconds']} | {e['risk']['score']} ({e['risk']['level']}) | {flags} |"
            )
    else:
        lines.append("_no engagements_")
    lines.append("")

    iocs = report.get("iocs") or []
    lines.append("## Detected IOCs")
    lines.append("")
    if iocs:
        lines.append("| kind | value | note |")
        lines.append("|---|---|---|")
        for ioc in iocs:
            lines.append(f"| {ioc.get('type')} | `{ioc.get('value')}` | {ioc.get('note', '')} |")
    else:
        lines.append("_none detected_")
    lines.append("")

    replay = report.get("replay") or []
    lines.append("## Interaction Replay")
    lines.append("")
    if replay:
        lines.append("```")
        lines.extend(replay)
        lines.append("```")
    else:
        lines.append("_no interactions_")
    lines.append("")

    lines.append("## Recommendation")
    lines.append("")
    lines.append(report.get("recommendation", "_none_"))
    lines.append("")
    return "\n".join(lines)