from pathlib import Path
import re
import unittest
from unittest.mock import patch

from preflight import status_check


ROOT = Path(__file__).resolve().parent.parent


class ReadinessAndUiSecurityTests(unittest.TestCase):
    def test_ordinary_web_page_keeps_native_setup_buttons_disabled_and_bridge_guarded(self):
        html = (ROOT / "preflight/static/index.html").read_text(encoding="utf-8")
        js = (ROOT / "preflight/static/native-setup.js").read_text(encoding="utf-8")
        swift = (ROOT / "macos/Preflight.swift").read_text(encoding="utf-8")

        for btn_id in ("configure-all", "restore-configuration", "configure-taiwan", "configure-vpn", "configure-firewall"):
            self.assertRegex(html, rf'id="{btn_id}"[^>]*disabled')
        # Plain browser without webkit.messageHandlers.preflight exits before enabling buttons
        self.assertIn("window.webkit?.messageHandlers?.preflight", js)
        self.assertIn('if (!bridge || typeof bridge.postMessage !== "function") return;', js)
        # Swift bridge strictly verifies main frame, loopback origin, exact port, and action allowlist
        self.assertIn("frame.isMainFrame", swift)
        self.assertIn('frame.securityOrigin.host == "127.0.0.1"', swift)
        self.assertIn("frame.securityOrigin.port == origin?.port", swift)
        self.assertIn("actions.contains(action)", swift)

    def test_ui_includes_all_six_sections_taiwan_constraint_and_honest_caveats(self):
        html = (ROOT / "preflight/static/index.html").read_text(encoding="utf-8")
        for anchor in ('href="#overview"', 'href="#network-checks"', 'href="#clients"',
                       'href="#mac-setup"', 'href="#history"', 'href="#settings"'):
            self.assertIn(anchor, html)
        self.assertIn("仅支持台湾", html)
        self.assertIn("LuLu", html)
        self.assertIn("VPN", html)
        self.assertIn("必须完全退出旧客户端", html)
        self.assertIn("轮询", html)
        self.assertIn("readonly", html)

    def test_readiness_snapshot_combines_components_without_secrets(self):
        with patch.object(status_check, "_region_status", return_value={"state": "ok", "configured": True}), \
             patch.object(status_check.vpn_setup, "inspect_vpn_status", return_value={"state": "ok", "activeApp": "OneVPN"}), \
             patch.object(status_check, "_lulu_status", return_value={"state": "pending", "installed": True}), \
             patch.object(status_check, "_claude_status", return_value={"state": "ok", "installed": True}), \
             patch.object(status_check, "_backups_status", return_value={"any": False, "region": False, "firewall": False, "vpn": False}):
            snap = status_check.collect_readiness()
        self.assertEqual(snap["overall"], "pending")
        self.assertTrue(snap["target"]["taiwanOnly"])
        self.assertEqual(snap["target"]["country"], "TW")
        self.assertEqual(snap["target"]["timezone"], "Asia/Taipei")


if __name__ == "__main__":
    unittest.main()
