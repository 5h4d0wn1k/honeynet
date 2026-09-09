"""dwell.py — dwell-time & risk scoring.

From an engagement: time-on-box, action count, protocol breadth and attack
flags (tool UA, path probing, credential reuse, honeytoken tripwires) become a
deterministic 0-100 risk score plus an IOC list. All quantities are derived
from the interaction log — nothing here ever touches the network.
"""

from __future__ import annotations

from typing import Any

from .engage import Engagement, METADATA_EVENTS, fingerprint_engagement

DEFAULT_WEIGHTS = {
    "dwell_max_pts": 30,
    "dwell_per_sec": 2.0,
    "actions_max_pts": 25,
    "actions_per_action": 3.0,
    "protocol_bonus": 3,
    "protocol_cap": 4,
    "flag_bonus": 5,
    "tripwire_bonus": 10,
}

LEVELS = [
    (20, "low"),
    (45, "medium"),
    (75, "high"),
    (101, "critical"),
]


def clamp(n: float, lo: float = 0.0, hi: float = 100.0) -> int:
    return int(max(lo, min(hi, n)))


def risk_level(score: int) -> str:
    for threshold, label in LEVELS:
        if score < threshold:
            return label
    return "critical"


def components(eng: Engagement, weights: dict[str, Any] | None = None) -> dict[str, Any]:
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    dwell = eng.dwell_seconds()
    dwell_pts = min(w["dwell_max_pts"], dwell * w["dwell_per_sec"])
    actions = eng.action_count()
    actions_pts = min(w["actions_max_pts"], actions * w["actions_per_action"])
    breadth = min(w["protocol_cap"], len(eng.protocols)) * w["protocol_bonus"]
    fg = [f for f in eng.flags if not f.startswith("honeytoken-tripwire")]
    flag_pts = min(25, len(fg) * w["flag_bonus"])
    if eng.tripwires:
        flag_pts = min(25, flag_pts + w["tripwire_bonus"])
    return {
        "dwell_seconds": round(dwell, 3),
        "actions": actions,
        "dwell_pts": round(dwell_pts, 3),
        "actions_pts": round(actions_pts, 3),
        "breadth_pts": float(breadth),
        "flag_pts": flag_pts,
        "protocols": len(eng.protocols),
    }


def compute_score(eng: Engagement, weights: dict[str, Any] | None = None) -> int:
    fingerprint_engagement(eng)
    comp = components(eng, weights)
    raw = comp["dwell_pts"] + comp["actions_pts"] + comp["breadth_pts"] + comp["flag_pts"]
    return clamp(raw)


def score_engagement(eng: Engagement, weights: dict[str, Any] | None = None) -> dict[str, Any]:
    comp = components(eng, weights)
    score = compute_score(eng, weights)
    return {
        **eng.summary(),
        "risk": {"score": score, "level": risk_level(score), "components": comp},
    }


def build_iocs(eng: Engagement) -> list[dict[str, str]]:
    """Deterministic IOC list for one engagement (placeholders only)."""
    iocs: list[dict[str, str]] = []
    iocs.append({"type": "source-ip", "value": eng.src, "note": "RFC 5737 test-net source (lab)"})
    for ua in sorted(eng.user_agents):
        iocs.append({"type": "user-agent", "value": ua, "note": "tool-signature UA"})
    for path, count in sorted(eng.paths.items()):
        iocs.append({"type": "path", "value": path, "note": f"probed x{count}"})
    for (user, password) in sorted(eng.credentials):
        iocs.append({"type": "credential-attempt", "value": f"{user}:{password}", "note": "rejected by honeypot"})
    for tw in eng.tripwires:
        iocs.append({"type": "honeytoken", "value": tw.get("token", ""), "note": f"tripwire {tw.get('path', '')}"})
    for topic in sorted(eng.topics):
        iocs.append({"type": "mqtt-subscribe", "value": topic, "note": "leak-topic probe"})
    for tool in sorted(eng.tools):
        iocs.append({"type": "mcp-tool-call", "value": tool, "note": "fake-tool invocation"})
    return iocs


def score_all(engagements: list[Engagement], weights: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    scored = [score_engagement(e, weights) for e in engagements]
    scored.sort(key=lambda s: s["risk"]["score"], reverse=True)
    return scored


def dwell_stats(scored: list[dict[str, Any]]) -> dict[str, Any]:
    if not scored:
        return {"engagements": 0}
    dwells = [s["dwell_seconds"] for s in scored]
    scores = [s["risk"]["score"] for s in scored]
    return {
        "engagements": len(scored),
        "total_actions": sum(s["actions"] for s in scored),
        "max_dwell_s": max(dwells),
        "mean_dwell_s": round(sum(dwells) / len(dwells), 3),
        "max_risk": max(scores),
        "mean_risk": round(sum(scores) / len(scores), 2),
        "levels": {level: sum(1 for s in scored if s["risk"]["level"] == level)
                   for level in ("low", "medium", "high", "critical")},
    }