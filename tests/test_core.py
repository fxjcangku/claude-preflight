import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from preflight import core
from preflight.__main__ import main


def reading():
    return {"network": {"country": "TW", "ip": "192.0.2.1", "route": "测试", "error": None},
            "system": {"region": "TW", "language": "zh-Hans-TW",
                       "system_timezone": "Asia/Taipei", "terminal_timezone": "Asia/Taipei"},
            "time": "2026-01-01T00:00:00+00:00"}


class PreflightTests(unittest.TestCase):
    def test_equal_utc_offset_does_not_hide_different_iana_zone(self):
        sample = reading()
        sample["system"]["terminal_timezone"] = "Asia/Shanghai"
        self.assertEqual(core.evaluate(sample, core.DEFAULT_TARGET)["status"], "fail")

    def test_unknown_observations_block_launch(self):
        sample = reading()
        sample["network"]["country"] = None
        with patch("preflight.__main__.snapshot", return_value=sample), \
             patch("preflight.__main__.load_target", return_value=core.DEFAULT_TARGET), \
             patch("sys.argv", ["preflight", "run"]), patch("builtins.print"), \
             patch("preflight.guard.run_guard") as launch:
            self.assertEqual(main(), 2)
            launch.assert_not_called()

    def test_managed_commands_never_probe_on_a_missing_vpn(self):
        for args in (["run"], ["attach-desktop", "123"]):
            with self.subTest(args=args), patch("sys.argv", ["preflight", *args]), \
                 patch("builtins.print"), patch.object(core, "read_system", return_value=reading()["system"]), \
                 patch("preflight.__main__.load_target", return_value=core.DEFAULT_TARGET), \
                 patch.object(core, "probe_network") as standard, \
                 patch("preflight.guard._identity", side_effect=ValueError("offline")), \
                 patch("preflight.guard._trace_via_port") as request, \
                 patch("preflight.guard.run_guard") as launch:
                self.assertEqual(main(), 2)
                standard.assert_not_called()
                request.assert_not_called()
                launch.assert_not_called()

    def test_managed_snapshot_pins_verified_proxy_and_rechecks_identity(self):
        from preflight.guard import probe_guarded_network
        vpn = SimpleNamespace(port=29813)
        response = subprocess.CompletedProcess([], 0, b"h=claude.ai\nip=1.1.1.1\nloc=TW\n\n200")
        with patch.dict(os.environ, {"NO_PROXY": "*", "HTTPS_PROXY": "http://invalid:8792"}), \
             patch("preflight.guard._identity", side_effect=[vpn, vpn, vpn, SimpleNamespace(port=29814)]), \
             patch("preflight.guard.subprocess.run", return_value=response) as curl, \
             patch.object(core, "read_system", return_value=reading()["system"]):
            net = core.snapshot(network_probe=probe_guarded_network)["network"]
            self.assertEqual((net["country"], net["ip"]), ("TW", "1.1.1.1"))
            cmd = curl.call_args.args[0]
            self.assertEqual(cmd[cmd.index("--proxy") + 1], "http://127.0.0.1:29813")
            self.assertEqual(cmd[cmd.index("--noproxy") + 1], "")
            self.assertFalse(any("proxy" in k.lower() for k in curl.call_args.kwargs["env"]))
            with self.assertRaisesRegex(ValueError, "状态已变化"):
                probe_guarded_network()

    def test_independent_check_still_uses_the_default_network_probe(self):
        with patch("sys.argv", ["preflight", "check"]), patch("builtins.print"), \
             patch("preflight.__main__.load_target", return_value=core.DEFAULT_TARGET), \
             patch.object(core, "read_system", return_value=reading()["system"]), \
             patch.object(core, "probe_network", return_value=reading()["network"]) as standard:
            self.assertEqual(main(), 0)
            standard.assert_called_once_with()

    def test_language_is_independent_of_target_region(self):
        self.assertEqual(core.evaluate(reading(), core.DEFAULT_TARGET)["status"], "pass")

    def test_targets_round_trip_without_saving_probe_history(self):
        with tempfile.TemporaryDirectory() as home:
            location = Path(home) / "app" / "target.json"
            with patch.object(core, "preferences_path", return_value=location):
                self.assertEqual(core.load_target(), core.DEFAULT_TARGET)
                target = core.validate_target("jp", "Asia/Tokyo")
                core.save_target(target)
                self.assertEqual(core.load_target(), target)
                self.assertEqual(json.loads(location.read_text()), target)

    def test_invalid_target(self):
        for country, zone in [("QQ", "UTC"), ("TW", "../zone"), ("TW", "Area/Missing")]:
            with self.subTest(country=country, zone=zone), self.assertRaises(ValueError):
                core.validate_target(country, zone)
