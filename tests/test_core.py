import json
import tempfile
import unittest
from pathlib import Path
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
             patch("os.execvp") as launch:
            self.assertEqual(main(), 2)
            launch.assert_not_called()

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
