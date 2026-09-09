import unittest

from tests.helpers import MqttClient, start_farm


class TestMqttHoneypot(unittest.TestCase):
    def test_connect_and_connack(self):
        farm, logger, ports = start_farm(["mqtt"])
        try:
            client = MqttClient(ports["mqtt"])
            try:
                connack = client.connect("lab-attacker")
                self.assertEqual(connack, b"\x20\x02\x00\x00")
                self.assertTrue(any(r["event"] == "connect-attempt" for r in logger.read()))
            finally:
                client.close()
        finally:
            farm.stop()

    def test_subscribe_logs_topic(self):
        farm, logger, ports = start_farm(["mqtt"])
        try:
            client = MqttClient(ports["mqtt"])
            try:
                client.connect("lab-attacker")
                client.subscribe("firmware/update/status")
                subs = [r for r in logger.read() if r["event"] == "subscribe"]
                self.assertEqual(len(subs), 1)
                self.assertEqual(subs[0]["data"]["topic"], "firmware/update/status")
                self.assertEqual(subs[0]["data"]["leak"], False)
            finally:
                client.close()
        finally:
            farm.stop()

    def test_subscribe_to_leak_topic_serves_fake_telemetry(self):
        farm, logger, ports = start_farm(["mqtt"])
        try:
            client = MqttClient(ports["mqtt"])
            try:
                client.connect("lab-attacker")
                packets = client.subscribe("telemetry/edge/#")
                kinds = {p[0] for p in packets}
                self.assertIn(0x90, kinds)  # SUBACK
                self.assertTrue(any(p[0] == 0x30 for p in packets), "expected fake PUBLISH")
                subs = [r for r in logger.read() if r["event"] == "subscribe"]
                self.assertEqual(subs[0]["data"]["leak"], True)
                out_publishes = [r for r in logger.read() if r["event"] == "publish" and r.get("direction") == "out"]
                self.assertEqual(len(out_publishes), 1)
                self.assertIn("gateway", str(out_publishes[0]["data"]))
            finally:
                client.close()
        finally:
            farm.stop()

    def test_publish_is_logged(self):
        farm, logger, ports = start_farm(["mqtt"])
        try:
            client = MqttClient(ports["mqtt"])
            try:
                client.connect("lab-attacker")
                from honeynet.protocol import mqtt_packet, mqtt_utf8
                topic = "firmware/a/b"
                payload = b"evil-payload"
                pub_body = mqtt_utf8(topic) + payload
                client.sock.sendall(mqtt_packet(0x30, pub_body))
                client.sock.sendall(b"\xe0\x00")
                import time
                time.sleep(0.3)
                pubs = [r for r in logger.read() if r["event"] == "publish"]
                self.assertEqual(len(pubs), 1)
                self.assertEqual(pubs[0]["data"]["topic"], "firmware/a/b")
            finally:
                client.close()
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()