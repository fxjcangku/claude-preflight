import http.client
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from preflight import server


TARGET = {"country": "TW", "timezone": "Asia/Taipei"}
READING = {"time": "2026-01-01T00:00:00Z", "network": {"country": "TW"},
           "system": {"region": "TW", "system_timezone": "Asia/Taipei",
                      "terminal_timezone": "Asia/Taipei"}}


class LocalServerTests(unittest.TestCase):
    def setUp(self):
        with patch.object(server, "load_target", return_value=dict(TARGET)):
            self.service = server._LocalServer(0)
        self.loop = threading.Thread(target=self.service.serve_forever, kwargs={"poll_interval": 0.01})
        self.loop.start()
        self.addCleanup(self.close)

    def close(self):
        self.service.shutdown()
        self.loop.join(2)
        self.service.server_close()

    def request(self, method, path, body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.service.server_port, timeout=3)
        try:
            client.request(method, path, body, headers or {})
            response = client.getresponse()
            return response.status, response.read()
        finally:
            client.close()

    def post(self, path, data):
        return self.request("POST", path, json.dumps(data), {
            "Origin": self.service.origin, "Content-Type": "application/json",
        })

    def test_initial_state_and_resources(self):
        status, result = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(result), {"history": [], "target": TARGET, "assessment": None,
                                              "launches": self.service.state.launches.status()})
        status, home = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"<html", home)

    def test_forbid_untrusted_origins_hosts_and_file_paths(self):
        for origin in ("http://external.invalid", "null", None):
            headers = {"Content-Type": "application/json"}
            if origin:
                headers["Origin"] = origin
            self.assertEqual(self.request("POST", "/api/check", "{}", headers)[0], 403)
        self.assertEqual(self.request("GET", "/api/state", headers={"Host": "else.invalid"})[0], 403)
        for path in ("/../preflight/core.py", "/about/%2e%2e/.git/config", "/static/", "/etc/passwd"):
            self.assertEqual(self.request("GET", path)[0], 404)

    def test_client_launch_requires_exact_payload_and_local_origin(self):
        manager = self.service.state.launches
        with patch.object(manager, "launch") as launch:
            self.assertEqual(self.request("POST", "/api/launch", '{"client":"web"}',
                                        {"Content-Type": "application/json"})[0], 403)
            for data in ({"client": "cli"}, {"client": ["web"]}, {"client": "web", "args": []}):
                self.assertEqual(self.post("/api/launch", data)[0], 400)
            launch.assert_not_called()
            status, body = self.post("/api/launch", {"client": "web"})
            self.assertEqual(status, 202)
            self.assertIn("launches", json.loads(body))
            launch.assert_called_once_with("web")
            launch.side_effect = ValueError("这个客户端已在启动或运行中")
            self.assertEqual(self.post("/api/launch", {"client": "web"})[0], 409)

    def test_invalid_content(self):
        headers = {"Origin": self.service.origin}
        self.assertEqual(self.request("POST", "/api/check", "{}", headers)[0], 415)
        headers["Content-Type"] = "application/json"
        for payload, expected in (("{", 400), ("null", 400), (" " * 4500, 413)):
            self.assertEqual(self.request("POST", "/api/check", payload, headers)[0], expected)
        self.assertEqual(self.post("/api/check", {"url": "example.invalid"})[0], 400)
        self.assertEqual(self.post("/api/settings", {"country": "US"})[0], 400)

    def test_settings_enforces_taiwan_only_and_reassesses_reading(self):
        with patch.object(server, "snapshot", return_value=READING):
            code, data = self.post("/api/check", {})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(data)["assessment"]["status"], "pass")
        with patch.object(server, "save_target") as save:
            code, err = self.post("/api/settings", {"country": "us", "timezone": "America/New_York"})
            self.assertEqual(code, 400)
            self.assertIn("仅支持台湾", json.loads(err)["error"])
            save.assert_not_called()
            code, data = self.post("/api/settings", {"country": "tw", "timezone": "Asia/Taipei"})
        self.assertEqual(code, 200)
        state = json.loads(data)
        save.assert_called_once_with({"country": "TW", "timezone": "Asia/Taipei"})
        self.assertEqual(state["assessment"]["status"], "pass")
        self.assertEqual(state["history"], [READING])

    def test_readiness_endpoint_returns_self_check_snapshot(self):
        fake = {"overall": "ok", "target": TARGET, "vpn": {"state": "ok"}}
        with patch("preflight.status_check.collect_readiness", return_value=fake):
            status, body = self.request("GET", "/api/readiness")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), fake)

    def test_pending_sample_shared_and_limit(self):
        sampling = threading.Event()
        joined = threading.Event()

        def sample():
            sampling.set()
            if not joined.wait(2):
                raise AssertionError("concurrent check did not join")
            return READING

        class ObservedFuture(server.Future):
            def result(self, timeout=None):
                joined.set()
                return super().result(timeout)

        with patch.object(server, "snapshot", side_effect=sample) as probe, patch.object(server, "Future", ObservedFuture):
            with ThreadPoolExecutor(2) as workers:
                first = workers.submit(self.post, "/api/check", {})
                self.assertTrue(sampling.wait(2))
                second = workers.submit(self.post, "/api/check", {})
                for job in (first, second):
                    status, data = job.result(3)
                    self.assertEqual(status, 200)
                    self.assertEqual(len(json.loads(data)["history"]), 1)
            probe.assert_called_once()
        with patch.object(server, "snapshot", side_effect=[dict(READING, time=str(i)) for i in range(61)]):
            for _ in range(61):
                state = self.service.state.check()
        self.assertEqual([s["time"] for s in state["history"]], [str(i) for i in range(1, 61)])


if __name__ == "__main__":
    unittest.main()
