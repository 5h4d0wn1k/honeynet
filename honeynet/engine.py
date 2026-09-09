"""engine.py — honeypot farm (server engine, the `pot` command).

Starts a configurable set of HoneypotService instances, each bound to its own
ephemeral loopback port, sharing one InteractionLogger and one DeceptionGrid.
Attribution lets a lab admin label the loopback peer as an RFC 5737 test
source (e.g. 127.0.0.1 -> 203.0.113.7) so engagements read like a real sensor
feed while still being fully localhost.
"""

from __future__ import annotations

import time
from typing import Any

from . import DEFAULT_BIND
from .config import default_config
from .deceive import DeceptionGrid, load_deception_grid
from .logger import InteractionLogger
from .services import FAMILIES, make_service


class Farm:
    def __init__(
        self,
        protos: list[str] | None = None,
        logger: InteractionLogger | None = None,
        deceive: DeceptionGrid | None = None,
        host: str = DEFAULT_BIND,
        attribution: dict[str, str] | None = None,
        ports: dict[str, int] | None = None,
        log_dir: str | None = None,
    ) -> None:
        self.protos = protos or [p for p in list(default_config()["services"])]
        self.host = host
        self.attribution = attribution or {}
        self.logger = logger or InteractionLogger(log_dir)
        self.deceive = deceive or DeceptionGrid()
        self.ports = ports or {}
        self.services = [
            make_service(p, self.logger, self.deceive, host=host, port=self.ports.get(p, 0), attribution=self.attribution)
            for p in self.protos
        ]

    def start(self) -> dict[str, int]:
        started: dict[str, int] = {}
        for svc in self.services:
            started[svc.proto] = svc.start()
        return started

    def port_map(self) -> dict[str, int]:
        return {svc.proto: svc.port for svc in self.services}

    def services_up(self) -> int:
        return sum(1 for s in self.services if s.running)

    def family_count(self) -> int:
        return len({FAMILIES[s.proto] for s in self.services})

    def families(self) -> set[str]:
        return {FAMILIES[s.proto] for s in self.services}

    def stop(self) -> None:
        for svc in reversed(self.services):
            svc.stop()

    def __enter__(self) -> "Farm":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def run_pot(
    protos: list[str] | None = None,
    duration: float = 3.0,
    config: dict[str, Any] | None = None,
    attribution: dict[str, str] | None = None,
    log_dir: str | None = None,
    host: str = DEFAULT_BIND,
    ports: dict[str, int] | None = None,
    auto_sim: bool = False,
) -> dict[str, Any]:
    """Stand up a farm, keep it up for `duration` seconds, tear down.

    auto_sim: run the offline attacker simulator against the farm while it is
    up and return its detection summary (used by `sim` and `--demo`).
    """
    cfg = config or default_config()
    grid = load_deception_grid(None, cfg)
    logger = InteractionLogger(log_dir or cfg.get("logger", {}).get("dir", "reports/honeypot"))
    farm = Farm(protos, logger=logger, deceive=grid, host=host, attribution=attribution or cfg.get("attribution", {}), ports=ports, log_dir=None)

    farm.start()
    listeners = farm.port_map()
    summary: dict[str, Any] = {
        "listeners": listeners,
        "families": sorted(farm.families()),
        "services_up": farm.services_up(),
    }
    sim_summary: dict[str, Any] | None = None

    try:
        if auto_sim:
            from .sim import run_standard_attack
            plan_cfg = cfg.get("sim", {})
            sim_summary = run_standard_attack(listeners, logger=logger, deceive=grid, cfg=plan_cfg)
            if duration:
                time.sleep(duration)
        elif duration:
            time.sleep(duration)
    finally:
        farm.stop()

    summary["interactions_logged"] = logger.count()
    summary["log_path"] = str(logger.path)
    summary["sim"] = sim_summary
    return summary