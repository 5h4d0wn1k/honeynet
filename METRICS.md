# Metrics

Real numbers measured from the offline demo (`python3 -m honeynet --demo`) and
the test suite (`python3 -m unittest discover -s tests`).

## Test Suite

| metric | value |
|---|---|
| tests | **100** |
| failures / errors | 0 / 0 |
| protocol families covered | 5 (ssh, http, telnet/smtp/vnc, mqtt, json-rpc/mcp) |
| real loopback sockets used | yes (tests bind ephemeral 127.0.0.1 ports) |
| leaked processes | none (confirmed after full suite) |

## Demo (`--demo`, offline, exit 0)

| metric | value |
|---|---|
| demo exit code | 0 |
| demo wall time | ~1.6 s |
| service families up | 5 |
| services up | 7 |
| sim attacker actions attempted | 9 |
| sim attacker replies served | 9 |
| interactions logged by sim attacker | 32 |
| dwell time T | 0.34 s |
| engagements | 1 |
| risk score | 62 / 100 (high) |
| detected IOCs | 9 |

### Detection accuracy (all sim attack steps detected)

| attack step | logged event(s) | detected |
|---|---|---|
| SSH banner + auth | `ssh banner-sent`, `auth-attempt`, `auth-rejected` | ✓ |
| HTTP GET `/` | `http request`, `login-page` | ✓ |
| HTTP POST creds | `http params` (user/pass parsed) | ✓ |
| HTTP tripwire `/config/secrets.env` | `http tripwire`, `honeytoken-served` | ✓ |
| MQTT subscribe leak topic | `mqtt subscribe` (leak:true) + fake `publish` | ✓ |
| MCP `tools/call read_secrets` | `mcp tool-call` (full request) | ✓ |
| telnet verbs | `telnet verb` | ✓ |
| SMTP verbs | `smtp verb` | ✓ |
| VNC handshake | `vnc verb` | ✓ |

### IOC breakdown (9)

- 1 × source-ip (RFC 5737: 203.0.113.7)
- 1 × user-agent (tool-signature: `sqlmap/1.7.2`)
- 3 × path (probed `/`, `/admin/login.php`, `/config/secrets.env`)
- 1 × credential-attempt (`root:********`, rejected)
- 1 × honeytoken (tripwire `/config/secrets.env`)
- 1 × mqtt-subscribe (`telemetry/edge/#`, leak-topic probe)
- 1 × mcp-tool-call (`read_secrets`)

_Record new measurements after each feature change._
