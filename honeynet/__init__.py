"""honeynet — honeypot farm + deception grid.

Pluggable multi-protocol honeypots (ssh, http, telnet/smtp/vnc, mqtt,
json-rpc/mcp) bound to loopback ephemeral ports, a shared JSONL interaction
logger, per-source engagement tracking with attack fingerprinting, dwell/risk
scoring, an offline attacker simulator, honeyplanted tokens with tripwires, and
source quarantine. Lab mode only (127.0.0.1, RFC5737 test-net placeholders).
"""

__version__ = "1.0.0"
__author__ = "5h4d0wn1k"
__license__ = "MIT"

APP_NAME = "honeynet"

DEFAULT_BIND = "127.0.0.1"

# RFC 5737 documentation/test IPv4 networks — the only "real world" identifiers
# this tool ever talks about. Never extended to production ranges.
RFC5737_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
LAB_HOSTS = ("127.0.0.1", "::1")