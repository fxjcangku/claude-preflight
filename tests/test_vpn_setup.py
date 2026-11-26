import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from preflight import vpn_setup as vpn


SAMPLE_YAML = """port: 7890
proxies:
  - {name: 最新地址example.invalid, server: 198.51.100.1, port: 443, type: ss}
  - {name: '极速|🇯🇵 日本 01', server: 198.51.100.2, port: 443, type: vless}
  - {name: '极速|🇹🇼 台湾 01', server: 198.51.100.3, port: 443, type: vless}
  - {name: '极速|🇹🇼 台湾 02', server: 198.51.100.4, port: 443, type: vless}
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - 最新地址example.invalid
      - '极速|🇯🇵 日本 01'
      - '极速|🇹🇼 台湾 01'
      - '极速|🇹🇼 台湾 02'
"""


def make_config(selected="极速|🇯🇵 日本 01", added_rules=None, enable=False, rule_type="added", override_rules=None):
    return {
        "currentProfileId": "prof-1",
        "windowProps": {"width": 900},
        "profiles": [
            {
                "id": "prof-1",
                "url": "https://secret-subscription.invalid/token=PRIVATE",
                "subscriptionInfo": {"upload": 1, "download": 2},
                "selectedMap": {"Proxies": selected, "GLOBAL": "DIRECT"},
                "overrideData": {
                    "enable": enable,
                    "rule": {
                        "type": rule_type,
                        "addedRules": list(added_rules or []),
                        "overrideRules": list(override_rules or []),
                    },
                },
            },
            {
                "id": "prof-2",
                "url": "https://second-sub.invalid/keep-me",
                "selectedMap": {},
                "overrideData": {"enable": False, "rule": {"type": "added", "addedRules": [], "overrideRules": []}},
            },
        ],
    }


class VpnSetupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.folder = self.root / "state"
        self.profiles = self.root / "profiles"
        self.profiles.mkdir()
        (self.profiles / "prof-1.yaml").write_text(SAMPLE_YAML, encoding="utf-8")
        self.fake_app = self.root / "OneVPN.app"
        self.fake_app.mkdir()
        self.config = make_config(
            added_rules=[{"id": "user-rule-1", "value": "DOMAIN-SUFFIX,example.org,DIRECT"}]
        )
        self.running_gui = [(100, 501, "start", "/Applications/OneVPN.app/Contents/MacOS/OneVPN")]
        self.identity = SimpleNamespace(port=7890, tunnels=(4,))

        for patcher in (
            patch.object(vpn.sys, "platform", "darwin"),
            patch.object(vpn, "_ONEVPN_APP", self.fake_app),
            patch.object(vpn, "_folder", return_value=self.folder),
            patch.object(vpn, "_profiles_dir", return_value=self.profiles),
            patch.object(vpn, "_read_flutter_config", side_effect=lambda: json.loads(json.dumps(self.config))),
            patch.object(vpn, "_write_flutter_config", side_effect=self._save_cfg),
            patch.object(vpn, "_onevpn_processes", side_effect=lambda: (list(self.running_gui), [])),
            patch.object(vpn.guard, "lock_sessions", return_value=(1, 0)),
            patch.object(vpn.guard, "_identity", side_effect=lambda: self.identity),
            patch.object(vpn.guard, "_trace_via_port", return_value=("TW", "198.51.100.88")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _save_cfg(self, updated):
        self.config = json.loads(json.dumps(updated))

    def test_three_phase_apply_preserves_subscriptions_and_restores_cleanly(self):
        original_snapshot = json.loads(json.dumps(self.config))
        prep = vpn.configure_vpn("apply", "prepare")
        self.assertEqual(prep["status"], "pending")
        self.assertEqual(prep["actionRequired"], "restartOneVPN")
        self.assertEqual(len(prep["candidates"]), 2)
        # Never leak subscription URL or raw node names
        serialized = json.dumps(prep, ensure_ascii=False)
        self.assertNotIn("secret-subscription", serialized)
        self.assertNotIn("极速|", serialized)

        # Commit fails if OneVPN is still running
        self.assertEqual(vpn.configure_vpn("apply", "commit", prep["node"])["status"], "error")

        # After OneVPN exits gracefully, commit merges rules and preserves subscriptions + user rules
        self.running_gui = []
        committed = vpn.configure_vpn("apply", "commit", prep["node"])
        self.assertEqual(committed["actionRequired"], "relaunchOneVPN")
        prof = self.config["profiles"][0]
        self.assertEqual(prof["url"], original_snapshot["profiles"][0]["url"])
        self.assertEqual(self.config["profiles"][1], original_snapshot["profiles"][1])
        self.assertEqual(prof["selectedMap"]["GLOBAL"], "DIRECT")
        self.assertEqual(prof["selectedMap"]["Proxies"], "极速|🇹🇼 台湾 01")
        self.assertTrue(prof["overrideData"]["enable"])
        values = [r["value"] for r in prof["overrideData"]["rule"]["addedRules"]]
        self.assertIn("DOMAIN-SUFFIX,example.org,DIRECT", values)
        for domain in vpn._CLAUDE_DOMAINS:
            self.assertIn(f"DOMAIN-SUFFIX,{domain},极速|🇹🇼 台湾 01", values)
        backup_file = self.folder / "vpn-setup.json"
        self.assertEqual(backup_file.stat().st_mode & 0o777, 0o600)

        # Verify confirms real TW exit
        verified = vpn.configure_vpn("apply", "verify", prep["node"])
        self.assertEqual(verified["status"], "ok")
        self.assertEqual(verified["measuredCountry"], "TW")

        # Repeated apply sees already-configured & verified TW without needing restart
        repeat = vpn.configure_vpn("apply", "prepare")
        self.assertEqual(repeat["status"], "ok")
        self.assertFalse(repeat["needRestart"])

        # Restore reverses ONLY Preflight changes and preserves user rule + subscriptions
        r_prep = vpn.configure_vpn("restore", "prepare")
        self.assertEqual(r_prep["actionRequired"], "restartOneVPN")
        r_commit = vpn.configure_vpn("restore", "commit")
        self.assertEqual(r_commit["actionRequired"], "relaunchOneVPN")
        self.assertEqual(r_commit["conflicts"], [])
        self.assertEqual(self.config, original_snapshot)
        self.assertFalse(backup_file.exists())

    def test_candidate_named_taiwan_but_non_tw_exit_is_rejected(self):
        prep = vpn.configure_vpn("apply", "prepare")
        self.running_gui = []
        self.assertEqual(vpn.configure_vpn("apply", "commit", prep["node"])["actionRequired"], "relaunchOneVPN")
        with patch.object(vpn.guard, "_trace_via_port", return_value=("JP", "198.51.100.99")):
            result = vpn.configure_vpn("apply", "verify", prep["node"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["measuredCountry"], "JP")
        self.assertTrue(result["retryable"])
        self.assertNotIn("198.51.100.99", result["message"])

    def test_no_taiwan_candidates_returns_clear_error(self):
        (self.profiles / "prof-1.yaml").write_text(
            "proxies:\n  - {name: '🇯🇵 日本 01', server: 198.51.100.2, port: 443, type: vless}\n",
            encoding="utf-8",
        )
        res = vpn.configure_vpn("apply", "prepare")
        self.assertEqual(res["status"], "error")
        self.assertIn("未找到台湾候选节点", res["message"])

    def test_existing_override_mode_rules_are_not_clobbered(self):
        self.config = make_config(enable=True, rule_type="override", override_rules=[{"id": "x", "value": "MATCH,DIRECT"}])
        prep = vpn.configure_vpn("apply", "prepare")
        self.running_gui = []
        res = vpn.configure_vpn("apply", "commit", prep["node"])
        self.assertEqual(res["status"], "error")
        self.assertIn("override", res["message"])

    def test_restore_detects_user_modified_node_and_rules_conflicts(self):
        prep = vpn.configure_vpn("apply", "prepare")
        self.running_gui = []
        vpn.configure_vpn("apply", "commit", prep["node"])
        # User manually switches node and edits one managed Claude rule
        prof = self.config["profiles"][0]
        prof["selectedMap"]["Proxies"] = "极速|🇹🇼 台湾 02"
        prof["overrideData"]["rule"]["addedRules"][0]["value"] = "DOMAIN-SUFFIX,anthropic.com,DIRECT"
        res = vpn.configure_vpn("restore", "commit")
        self.assertTrue(res["conflicts"])
        # User's manual choices are preserved
        self.assertEqual(self.config["profiles"][0]["selectedMap"]["Proxies"], "极速|🇹🇼 台湾 02")
        self.assertIn(
            "DOMAIN-SUFFIX,anthropic.com,DIRECT",
            [r["value"] for r in self.config["profiles"][0]["overrideData"]["rule"]["addedRules"]],
        )

    def test_unconfirmed_lock_blocks_prepare(self):
        with patch.object(vpn.guard, "lock_sessions", return_value=(0, 1)):
            res = vpn.configure_vpn("apply", "prepare")
        self.assertEqual(res["status"], "pending")
        self.assertEqual(res["actionRequired"], "quitClaude")

    def test_non_onevpn_universal_vpn_fallback_verifies_real_exit(self):
        missing_app = self.root / "MissingOneVPN.app"
        with patch.object(vpn, "_ONEVPN_APP", missing_app), \
             patch.object(vpn, "detect_installed_vpns", return_value=[{"name": "Clash Verge", "running": True, "autoConfigSupported": False}]), \
             patch.object(vpn, "_detect_system_proxy_info", return_value=(True, "HTTPS", "127.0.0.1:7897", 7897)), \
             patch.object(vpn, "_active_utun_interfaces", return_value=["utun5"]), \
             patch.object(vpn, "probe_network", return_value={"country": "TW", "ip": "198.51.100.7"}):
            ok = vpn.configure_vpn("apply", "prepare")
            self.assertEqual(ok["status"], "ok")
            self.assertIn("Clash Verge", ok["message"])
        with patch.object(vpn, "_ONEVPN_APP", missing_app), \
             patch.object(vpn, "detect_installed_vpns", return_value=[{"name": "Clash Verge", "running": True, "autoConfigSupported": False}]), \
             patch.object(vpn, "_detect_system_proxy_info", return_value=(True, "HTTPS", "127.0.0.1:7897", 7897)), \
             patch.object(vpn, "_active_utun_interfaces", return_value=["utun5"]), \
             patch.object(vpn, "probe_network", return_value={"country": "SG", "ip": "198.51.100.8"}):
            bad = vpn.configure_vpn("apply", "prepare")
            self.assertEqual(bad["status"], "error")
            self.assertEqual(bad["measuredCountry"], "SG")


if __name__ == "__main__":
    unittest.main()
