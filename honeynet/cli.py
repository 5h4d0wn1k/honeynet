"""cli.py — honeynet command-line interface.

Subcommands:
  pot        run the honeypot farm (pluggable services, ephemeral loopback ports)
  engage     engagement tracker: sessions per source, fingerprinting, dwell
  deceive    deception grid: show/list/tripwire test/honeyplanted tokens, write grid
  sim        scripted attacker replay against a live ephemeral farm
  dwell      dwell-time & risk scoring with IOC extraction
  report     JSON + Markdown reports (engagements, stats, replay, IOCs, recommendation)
  quarantine mark a lab source as 'kill' and filter future interactions

`--demo` runs the fully offline end-to-end proof and exits 0.
With no subcommand and no --demo, prints help.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from . import config as config_mod
from . import dwell as dwell_mod
from . import engage as engage_mod
from . import engine as engine_mod
from . import quarantine as quarantine_mod
from . import report as report_mod
from . import sim as sim_mod
from .config import default_config
from .deceive import DeceptionGrid, load_deception_grid
from .logger import InteractionLogger


def _jprint(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _load_records(path: str | None) -> list[dict[str, Any]]:
    p = Path(path) if path else Path("reports") / "honeypot" / "interactions.jsonl"
    if not p.exists():
        raise FileNotFoundError(f"Interaction log not found: {p}")
    out: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _parse_ports(spec: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for tok in (spec or "").replace(",", " ").split():
        if "=" in tok:
            k, v = tok.split("=", 1)
        elif ":" in tok:
            k, v = tok.split(":", 1)
        else:
            continue
        out[k] = int(v)
    return out


def _log_dir(args) -> str | None:
    return str((Path(args.report_dir) / "honeypot")) if args.report_dir else None


def cmd_pot(args) -> int:
    cfg = config_mod.load_config(args.config)
    protos = [p.strip() for p in (args.services or "").split(",") if p.strip()] or cfg["services"]
    ports = _parse_ports(args.ports or "")
    summary = engine_mod.run_pot(
        protos,
        duration=args.duration,
        config=cfg,
        attribution=cfg.get("attribution", {}),
        ports=ports,
        log_dir=_log_dir(args),
        host=cfg.get("bind", "127.0.0.1"),
        auto_sim=args.sim,
    )
    print(f"listeners: {json.dumps(summary['listeners'])}")
    print(f"families: {summary['families']}")
    print(f"services up: {summary['services_up']}")
    print(f"interactions logged: {summary['interactions_logged']} -> {summary['log_path']}")
    if summary.get("sim"):
        _print_sim(summary["sim"], "sim-attacker")
    return 0


def _print_sim(res: dict[str, Any], label: str) -> None:
    print(f"{label}: actions={res['actions_logged']} dwell={res['dwell_seconds']}s engagements={res['engagements']}")
    risk = res.get("risk") or {}
    print(f"{label}: score={risk.get('score')} level={risk.get('level')}")
    for ioc in res.get("iocs", []):
        print(f"  ioc[{ioc.get('type')}] {ioc.get('value')}: {ioc.get('note')}")
    replay = res.get("replay", [])
    print(f"{label}: replay ({len(replay)} lines):")
    for line in replay[:12]:
        print(f"   {line}")


def cmd_engage(args) -> int:
    records = _load_records(args.log)
    tracker = engage_mod.tracker_from_records(records)
    results = tracker.results()
    _jprint({
        "sources": len(results),
        "records": len(records),
        "engagements": results,
    })
    return 0


def cmd_deceive(args) -> int:
    cfg = config_mod.load_config(args.config)
    grid = load_deception_grid(args.grid, cfg)
    if args.action == "show":
        _jprint(grid.to_dict())
    elif args.action == "tokens":
        out = []
        for asset in grid.assets:
            if asset.get("tripwire"):
                out.append({"path": asset["path"], "token": grid.honeytoken_for(asset["path"]), "tripwire": True})
        _jprint({"root": grid.root, "tokens": out, "prefix": "HNYTKN-"})
    elif args.action == "tripwire":
        _jprint({"path": args.path, "is_tripwire": grid.is_tripwire(args.path), "token": grid.honeytoken_for(args.path)})
    elif args.action == "write":
        path = args.out
        grid.save(path)
        print(f"grid written: {path}")
    return 0


def cmd_sim(args) -> int:
    cfg = config_mod.load_config(args.config)
    protos = [p.strip() for p in (args.services or "").split(",") if p.strip()] or cfg["services"]
    grid = load_deception_grid(None, cfg)
    log_dir = args.report_dir + "/honeypot" if args.report_dir else cfg.get("logger", {}).get("dir", "reports/honeypot")
    logger = InteractionLogger(log_dir)
    sim_cfg = dict(cfg.get("sim", {}))
    if args.attacker_src:
        sim_cfg["attacker_src"] = args.attacker_src
    if args.ua:
        sim_cfg["attacker_ua"] = args.ua

    farm = engine_mod.Farm(protos, logger=logger, deceive=grid, host=cfg.get("bind", "127.0.0.1"),
                           attribution=cfg.get("attribution", {}), ports=_parse_ports(args.ports or ""))
    farm.start()
    try:
        listeners = farm.port_map()
        print(f"farm up: {json.dumps(listeners)} (families={sorted(farm.families())})")
        res = sim_mod.run_standard_attack(listeners, logger, deceive=farm.deceive, cfg=sim_cfg)
    finally:
        farm.stop()

    _print_sim(res, "attacker")
    if args.report:
        report = report_mod.build_report(
            records=logger.read(),
            engagements=res["scored"],
            dwell_stats=res["stats"],
            iocs=res["iocs"],
            recommendation=report_mod.recommender(res["scored"]),
            meta={"mode": "sim", "note": "offline lab simulation on loopback ephemeral ports"},
        )
        rep_dir = args.report_dir or cfg.get("report", {}).get("dir", "reports")
        json_path, md_path = report_mod.write_reports(report, rep_dir)
        print(f"reports: {json_path}\n         {md_path}")
    return 0


def cmd_dwell(args) -> int:
    cfg = config_mod.load_config(args.config)
    records = _load_records(args.log)
    tracker = engage_mod.tracker_from_records(records)
    scored = dwell_mod.score_all(tracker.engagements(fingerprints=True), cfg.get("dwell"))
    out = {
        "stats": dwell_mod.dwell_stats(scored),
        "engagements": scored,
    }
    if args.iocs:
        out["iocs"] = []
        for eng in tracker.engagements(fingerprints=True):
            out["iocs"].extend(dwell_mod.build_iocs(eng))
    _jprint(out)
    return 0


def cmd_report(args) -> int:
    cfg = config_mod.load_config(args.config)
    records = _load_records(args.log)
    tracker = engage_mod.tracker_from_records(records)
    engagements = tracker.engagements(fingerprints=True)
    scored = dwell_mod.score_all(engagements, cfg.get("dwell"))
    iocs: list[dict[str, str]] = []
    for eng in engagements:
        for ioc in dwell_mod.build_iocs(eng):
            if ioc not in iocs:
                iocs.append(ioc)
    report = report_mod.build_report(
        records=records,
        engagements=scored,
        dwell_stats=dwell_mod.dwell_stats(scored),
        iocs=iocs,
        recommendation=report_mod.recommender(scored),
        meta={"note": "aggregated from interaction log"},
    )
    rep_dir = args.report_dir or cfg.get("report", {}).get("dir", "reports")
    json_path, md_path = report_mod.write_reports(report, rep_dir)
    print(f"engagements: {len(scored)}  records: {len(records)}")
    print(f"json: {json_path}")
    print(f"md:   {md_path}")
    return 0


def cmd_quarantine(args) -> int:
    cfg = config_mod.load_config(args.config)
    qpath = args.file or cfg.get("quarantine", {}).get("file", "reports/quarantine.json")
    q = quarantine_mod.Quarantine(path=qpath, dry_run=not args.confirm)
    if args.action == "kill":
        res = q.mark_kill(args.src, reason=args.reason)
        print(json.dumps(res))
        if res["dry_run"]:
            print("dry-run: pass --confirm to persist to", qpath)
    elif args.action == "unmark":
        print(json.dumps(q.unmark(args.src)))
    elif args.action == "status":
        print(json.dumps(q.status(), indent=2))
    elif args.action == "scan":
        records = _load_records(args.log)
        suppressed = q.interceptions(records)
        kept = q.filter_interactions(records)
        shown = [{"src": r.get("src"), "proto": r.get("proto"), "event": r.get("event")} for r in suppressed[:20]]
        print(json.dumps({
            "quarantined": q.killed_sources(),
            "records_scanned": len(records),
            "interceptions_suppressed": len(suppressed),
            "records_kept": len(kept),
            "suppressed": shown,
            "dry_run": q.dry_run,
        }, indent=2))
    return 0


def run_demo() -> int:
    """Fully offline end-to-end proof. Exits 0 with real output."""
    print("== honeynet offline demo ==")
    tmpdir = tempfile.mkdtemp(prefix="honeynet-demo-")
    cfg = default_config()
    rep_dir = f"{tmpdir}/reports"
    log_dir = f"{rep_dir}/honeypot"
    sim_cfg = dict(cfg["sim"])
    attacker_src = sim_cfg["attacker_src"]  # 203.0.113.7 (RFC 5737)

    grid = DeceptionGrid(seed=cfg["deception"]["seed"])
    logger = InteractionLogger(log_dir)
    protos = ["ssh", "http", "telnet", "smtp", "vnc", "mqtt", "mcp"]
    attribution = {"127.0.0.1": attacker_src}
    farm = engine_mod.Farm(protos, logger=logger, deceive=grid, host=cfg["bind"], attribution=attribution)
    farm.start()
    try:
        listeners = farm.port_map()
        print(f"5 service families up on ephemeral loopback ports: ssh, http, telnet/smtp/vnc, mqtt, json-rpc/mcp")
        print(f"services up: {farm.services_up()} (families={farm.family_count()})")
        print(f"listeners: {json.dumps(listeners)}")

        res = sim_mod.run_standard_attack(listeners, logger, deceive=grid, cfg=sim_cfg)
        attacker = res["attacker"]
        print(f"sim attacker logged with {res['actions_logged']} actions "
              f"({attacker['actions_attempted']} attempted, {attacker['actions_ok']} served replies) src={attacker['src']}")
        print(f"dwell T = {res['dwell_seconds']}s  engagements={res['engagements']}")
        risk = res["risk"]
        print(f"score: {risk['score']}/100 (level={risk['level']})")
        print("IOCs:")
        for ioc in res["iocs"]:
            print(f"  {ioc['type']}: {ioc['value']}  ({ioc['note']})")
        print("replay timeline:")
        for line in res["replay"]:
            print(f"  {line}")

        print("quarantine (dry-run):")
        q = quarantine_mod.Quarantine(path=f"{rep_dir}/quarantine.json", dry_run=True)
        print(f"  mark kill {attacker_src}: {q.mark_kill(attacker_src, 'demo detection')['marked']}")
        suppressed = q.interceptions(logger.read())
        kept = q.filter_interactions(logger.read())
        print(f"  interactions suppressed: {len(suppressed)}  kept: {len(kept)}")

        report = report_mod.build_report(
            records=logger.read(),
            engagements=res["scored"],
            dwell_stats=res["stats"],
            iocs=res["iocs"],
            recommendation=report_mod.recommender(res["scored"]),
            meta={"mode": "demo", "note": "offline lab simulation on loopback ephemeral ports"},
        )
        json_path, md_path = report_mod.write_reports(report, rep_dir)
        print(f"reports: {json_path}\n         {md_path}")
    finally:
        farm.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeynet", description="Honeypot farm + deception grid (offline lab-only)")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--demo", action="store_true", help="run the offline end-to-end demo")

    sub = parser.add_subparsers(dest="subcommand")

    p_pot = sub.add_parser("pot", help="run the honeypot farm on ephemeral loopback ports")
    p_pot.add_argument("--services", default=None, help="comma-separated protos: ssh,http,telnet,smtp,vnc,mqtt,mcp")
    p_pot.add_argument("--duration", type=float, default=2.0, help="how long to listen (s)")
    p_pot.add_argument("--ports", default=None, help="proto=port[,proto=port...] (>=1024 loopback only)")
    p_pot.add_argument("--config", default=None)
    p_pot.add_argument("--report-dir", default=None)
    p_pot.add_argument("--sim", action="store_true", help="run the attacker simulator against the farm")
    p_pot.set_defaults(func=cmd_pot)

    p_eng = sub.add_parser("engage", help="engagement tracker + fingerprinting")
    p_eng.add_argument("--log", default=None, help="interactions.jsonl path")
    p_eng.add_argument("--config", default=None)
    p_eng.set_defaults(func=cmd_engage)

    p_dec = sub.add_parser("deceive", help="deception grid configurator")
    p_dec.add_argument("action", choices=["show", "tokens", "tripwire", "write"])
    p_dec.add_argument("--path", default=None, help="asset path for tripwire/token queries")
    p_dec.add_argument("--out", default=None, help="write grid to YAML/JSON file")
    p_dec.add_argument("--grid", default=None, help="existing grid config file")
    p_dec.add_argument("--config", default=None)
    p_dec.set_defaults(func=cmd_deceive)

    p_sim = sub.add_parser("sim", help="scripted attacker replay against a live ephemeral farm")
    p_sim.add_argument("--services", default=None)
    p_sim.add_argument("--config", default=None)
    p_sim.add_argument("--report-dir", default=None)
    p_sim.add_argument("--ports", default=None)
    p_sim.add_argument("--attacker-src", default=None, help="RFC 5737 attribution label (default 203.0.113.7)")
    p_sim.add_argument("--ua", default=None)
    p_sim.add_argument("--report", action="store_true", help="write JSON+Markdown reports")
    p_sim.set_defaults(func=cmd_sim)

    p_dw = sub.add_parser("dwell", help="dwell-time & risk scoring + IOCs")
    p_dw.add_argument("--log", default=None)
    p_dw.add_argument("--config", default=None)
    p_dw.add_argument("--iocs", action="store_true")
    p_dw.set_defaults(func=cmd_dwell)

    p_rep = sub.add_parser("report", help="JSON + Markdown engagement report")
    p_rep.add_argument("--log", default=None)
    p_rep.add_argument("--config", default=None)
    p_rep.add_argument("--report-dir", default=None)
    p_rep.set_defaults(func=cmd_report)

    p_q = sub.add_parser("quarantine", help="mark a lab source as 'kill' and filter interactions")
    p_q.add_argument("action", choices=["kill", "unmark", "status", "scan"])
    p_q.add_argument("--src", default=None, help="RFC 5737 / loopback source to quarantine")
    p_q.add_argument("--reason", default=None)
    p_q.add_argument("--file", default=None, help="quarantine JSON store")
    p_q.add_argument("--log", default=None)
    p_q.add_argument("--config", default=None)
    p_q.add_argument("--confirm", action="store_true", help="persist the kill (default dry-run)")
    p_q.set_defaults(func=cmd_quarantine)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.demo:
        return run_demo()

    if not getattr(args, "subcommand", None):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001
        print(f"honeynet: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())