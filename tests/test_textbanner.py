import unittest

from honeynet.deceive import DeceptionGrid
from tests.helpers import start_farm


def telnet_exchange(port, lines):
    import socket
    from honeynet.protocol import recv_until
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        banner = recv_until(sock, b"login: ", timeout=5)
        for i, line in enumerate(lines):
            sock.sendall((line + "\r\n").encode("utf-8"))
            recv_until(sock, b"Password: " if i == 0 else b"$ ", timeout=5)
        sock.sendall(b"\r\n")
        return banner
    finally:
        sock.close()


def smtp_exchange(port, verbs):
    import socket
    from honeynet.protocol import recv_line
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        greeting = recv_line(sock, timeout=5)
        for verb in verbs:
            sock.sendall((verb + "\r\n").encode("utf-8"))
            recv_line(sock, timeout=3)
        return greeting
    finally:
        sock.close()


def vnc_exchange(port):
    import socket
    from honeynet.protocol import recv_exact, recv_line
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        version = recv_line(sock, timeout=5)
        sock.sendall(version)
        security = recv_exact(sock, 4, timeout=5)
        sock.sendall(b"\x00")
        result = recv_exact(sock, 4, timeout=5)
        return version, security, result
    finally:
        sock.close()


class TestTelnetHoneypot(unittest.TestCase):
    def test_banner_and_verb_logging(self):
        farm, logger, ports = start_farm(["telnet"])
        try:
            banner = telnet_exchange(ports["telnet"], ["admin", "whoami"])
            self.assertIn(b"Ubuntu 22.04.3", banner)
            verbs = [r for r in logger.read() if r["event"] == "verb"]
            texts = {v["data"]["verb"] for v in verbs}
            self.assertIn("admin", texts)
            self.assertIn("whoami", texts)
        finally:
            farm.stop()


class TestSmtpHoneypot(unittest.TestCase):
    def test_banner_and_verb_logging(self):
        farm, logger, ports = start_farm(["smtp"])
        try:
            greeting = smtp_exchange(ports["smtp"], ["EHLO attacker.example",
                                                     "MAIL FROM:<root@attacker.local>",
                                                     "RCPT TO:<root@honeynet.lab>"])
            self.assertIn(b"220", greeting)
            verbs = [r["data"]["verb"] for r in logger.read() if r["event"] == "verb"]
            self.assertTrue(any(v.upper().startswith("EHLO") for v in verbs))
            self.assertTrue(any(v.upper().startswith("MAIL") for v in verbs))
            self.assertTrue(any(v.upper().startswith("RCPT") for v in verbs))
        finally:
            farm.stop()


class TestVncMockHoneypot(unittest.TestCase):
    def test_handshake_logged(self):
        farm, logger, ports = start_farm(["vnc"])
        try:
            version, security, result = vnc_exchange(ports["vnc"])
            self.assertEqual(version.strip(), b"RFB 003.008")
            panic = security
            self.assertEqual(len(panic), 4)
            verbs = [r["data"]["verb"] for r in logger.read() if r["event"] == "verb"]
            self.assertTrue(any("RFB" in v for v in verbs), verbs)
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()