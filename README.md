# honeynet

Honeypot farm + deception grid — multi-protocol honeypots on loopback ephemeral
ports, engagement tracking with attack fingerprinting, dwell/risk scoring,
attacker simulation, interaction replay, an MCP-honeypot mode, and per-source
quarantine.

- **Pluggable honeypots**: SSH / HTTP / telnet / MQTT / MCP (JSON-RPC)
- **Shared JSONL interaction logger** under `reports/honeypot/`
- **Engagement tracker** with credential-reuse, tool-UA and path-probe fingerprinting
- **Dwell & risk scoring** with IOC extraction (RFC 5737 sources only, placeholders)
- **Offline attacker simulator** proving detection end-to-end
- **MCP-honeypot**: fake tool catalogue + full tool-call capture
- **Honeyplanted tokens** + tripwires, runtime-constructed (never committed)
- **Source quarantine** (loopback / RFC 5737 only; dry-run first)

Runs entirely on `127.0.0.1` with ephemeral ports. Lab-only. Tests bind real
loopback sockets and simulate attacker interaction.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

```bash
python3 -m pip install -e ".[full]"
python3 -m honeynet --help
python3 -m honeynet --demo        # offline end-to-end proof, exit 0
python3 -m unittest discover -s tests
```

## Subcommands

| command | purpose |
|---|---|
| `pot` | run the honeypot farm (`--services ssh,http,telnet,mqtt,mcp`), optional `--sim` |
| `engage` | engagement tracker + attack fingerprinting, grouped per source |
| `deceive` | deception grid: `show` / `tokens` / `tripwire` / `write` |
| `sim` | scripted attacker replay against a live ephemeral farm |
| `dwell` | dwell-time & risk scoring + IOC extraction |
| `report` | JSON + Markdown engagement report to `reports/` |
| `quarantine` | mark a lab source as `kill` and filter future interactions |

## Live Lab Test Plan

When you have your **own** lab with written authorization, exercise the farm
against real loopback listeners and capture proof output. Expected proof for
each service:

- **SSH**: `pot --services ssh --sim` → interaction log contains an `auth-attempt`
  with the simulated username/password and `auth-rejected: True`.
- **HTTP**: `pot --services http --sim` → GET/POST params parsed and logged; a
  `tripwire` hit on `/config/secrets.env` serves the planted `HNYTKN-…` token and
  logs `honeytoken-served`.
- **telnet / dt**: banner + every verb (`admin`, `whoami`) logged as `verb`.
- **MQTT**: `mqtt_subscribe` to a leak topic (`telemetry/edge/#`) → `subscribe`
  with `leak: true`, then a fake-telemetry `publish` (out) containing the gateway.
- **MCP / json-rpc**: `tools/call` logged with the **full request**; fake tool
  result returned.

Run `python3 -m honeynet pot --services ssh,http,telnet,mqtt,mcp --sim --report-dir reports`
and verify `reports/honeypot/interactions.jsonl` plus the JSON/Markdown reports
under `reports/`. Quarantine the simulated source (`quarantine kill --src
203.0.113.7 --confirm`) and confirm `scan` suppresses those interactions.

## Metrics

See [`METRICS.md`](METRICS.md) for measured numbers (tests, detection accuracy,
timings). Measure and record after each feature change.

## Safety gates

- Services refuse any non-loopback bind and any non-loopback peer.
- Only RFC 5737 test-net or loopback sources may be quarantined.
- `quarantine` is dry-run by default; `--confirm` persists.
- Fake creds / keys / honeytokens are runtime-constructed placeholders — never
  committed secrets, never real tokens.

## License

MIT — see [LICENSE](LICENSE). Authorized testing/education only; see the legal
notice above.
