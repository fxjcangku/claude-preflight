import os
import subprocess
import unittest
from unittest.mock import patch

from preflight import network


class NetworkProbeTests(unittest.TestCase):
    def probe(self, payload, http=200, returncode=0, proxy=None):
        reply = subprocess.CompletedProcess([], returncode, stdout=(
            payload.encode() + f"\n{http:03d} 0.125".encode()
        ))
        with patch.object(network, "_select_proxy", return_value=("test", proxy)):
            with patch.object(network.subprocess, "run", return_value=reply) as runner:
                result = network.probe_network()
        return result, runner.call_args

    def test_valid_trace_and_proxy_credentials(self):
        proxy = "http://user:password@localhost:8080"
        result, call = self.probe("h=claude.ai\nip=8.8.8.8\nloc=TW\n", proxy=proxy)
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["country"], "TW")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["latency_ms"], 125)
        self.assertIsNone(result["error"])
        self.assertNotIn("password", repr(result))
        self.assertNotIn("password", repr(call.args))
        self.assertEqual(call.kwargs["env"]["https_proxy"], proxy)

    def test_private_malformed_and_unexpected_replies(self):
        for payload in (
            "<html>Challenge</html>", "h=claude.ai\nip=10.0.0.1\nloc=TW",
            "h=claude.ai\nip=8.8.8.8\nloc=ZZ", "h=other\nip=8.8.8.8\nloc=TW",
            "h=claude.ai\nip=8.8.8.8\nloc=TW\nloc=US",
        ):
            with self.subTest(payload=payload):
                result, _ = self.probe(payload)
                self.assertIsNone(result["ip"])
                self.assertIsNone(result["country"])
                self.assertIsNotNone(result["error"])
                self.assertEqual(result["http_status"], 200)

    def test_real_http_status_survives_errors(self):
        for code, rc in ((302, 0), (403, 0), (429, 0), (200, 63)):
            with self.subTest(code=code, curl_returncode=rc):
                result, _ = self.probe("h=claude.ai\nip=8.8.8.8\nloc=TW", code, rc)
                self.assertEqual(result["http_status"], code)
                self.assertIsNone(result["country"])
                self.assertIsNotNone(result["error"])

    def test_connection_error(self):
        result, _ = self.probe("", 0, 7)
        self.assertIsNone(result["http_status"])
        self.assertIsNone(result["latency_ms"])
        self.assertIsNotNone(result["error"])

    def test_env_precedence_and_bypass(self):
        with patch.dict(os.environ, {"ALL_PROXY": "http://all:123", "https_proxy": "http://secure:456"}, clear=True):
            self.assertEqual(network._select_proxy()[1], "http://secure:456")
            os.environ["no_proxy"] = ".claude.ai"
            self.assertIsNone(network._select_proxy()[1])

    def test_mac_proxy_fallbacks(self):
        def proxy_settings(contents):
            return subprocess.CompletedProcess([], 0, stdout=contents.encode())
        manual = "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : 127.0.0.1\n  HTTPSPort : 7890\n}"
        pac = "<dictionary> {\n  ProxyAutoConfigEnable : 1\n}"
        with patch.dict(os.environ, {"NO_PROXY": "localhost"}, clear=True):
            with patch.object(network.subprocess, "run", side_effect=[proxy_settings(manual), proxy_settings("0")]):
                self.assertEqual(network._select_proxy(), ("系统 HTTPS 代理", "http://127.0.0.1:7890"))
            with patch.object(network.subprocess, "run", side_effect=[proxy_settings(pac), proxy_settings("0")]):
                self.assertIsNotNone(network.probe_network()["error"])


if __name__ == "__main__":
    unittest.main()
