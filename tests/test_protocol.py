import unittest

from honeynet.protocol import (
    decode_remaining_length,
    http_bytes,
    jsonrpc_request,
    mqtt_remaining_length,
    parse_http_request,
    parse_mqtt_connect,
    parse_mqtt_publish,
    parse_mqtt_subscribe,
)


class TestMqttFraming(unittest.TestCase):
    def test_remaining_length_roundtrip(self):
        for n in [0, 1, 63, 127, 128, 255, 16383, 16384, 2097151, 268435455]:
            encoded = mqtt_remaining_length(n)
            value, _ = decode_remaining_length(encoded, 0)
            self.assertEqual(value, n)

    def test_subscribe_parse(self):
        body = (7).to_bytes(2, "big") + (16).to_bytes(2, "big") + b"telemetry/edge/#" + b"\x01"
        entries = parse_mqtt_subscribe(body)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["packet_id"], 7)
        self.assertEqual(entries[0]["topic"], "telemetry/edge/#")
        self.assertEqual(entries[0]["qos"], 1)

    def test_connect_parse(self):
        import struct
        vh = (4).to_bytes(2, "big") + b"MQTT" + bytes([4, 0x02]) + (60).to_bytes(2, "big") + (6).to_bytes(2, "big") + b"client"
        info = parse_mqtt_connect(vh)
        self.assertEqual(info["client_id"], "client")
        self.assertTrue(info["clean_session"])
        self.assertEqual(info["keepalive"], 60)
        self.assertEqual(info["level"], 4)

    def test_publish_parse(self):
        info = parse_mqtt_publish((5).to_bytes(2, "big") + b"a/b/c" + b"hello")
        self.assertEqual(info["topic"], "a/b/c")
        self.assertEqual(info["payload"], "hello")


class TestHttpParsing(unittest.TestCase):
    def test_parse_request(self):
        raw = b"POST /admin/login.php?x=1 HTTP/1.1\r\nHost: h.lab\r\nContent-Length: 2\r\n\r\nab"
        method, target, version, headers, body = parse_http_request(raw)
        self.assertEqual(method, "POST")
        self.assertEqual(target, "/admin/login.php?x=1")
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(headers["host"], "h.lab")
        self.assertEqual(body, b"ab")

    def test_http_bytes_build(self):
        data = http_bytes("GET", "/", {"User-Agent": "ua"}, "")
        self.assertTrue(data.startswith(b"GET / HTTP/1.1"))
        self.assertIn(b"User-Agent: ua", data)


class TestJsonRpc(unittest.TestCase):
    def test_jsonrpc_request(self):
        pkt = jsonrpc_request(42, "tools/call", {"name": "read_secrets"})
        self.assertTrue(pkt.startswith(b'{"jsonrpc":"2.0","id":42,"method":"tools/call"'))
        self.assertTrue(pkt.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()