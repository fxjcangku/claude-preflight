import os
import unittest
from unittest.mock import patch

from preflight import system_info


class SystemInfoTests(unittest.TestCase):
    def test_macos_uses_locale_region_and_keeps_terminal_override_separate(self):
        outputs = (
            "zh-Hans_TW",
            '(\n    "zh-Hans-HK",\n    "en-HK"\n)',
            "0",
            "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : private-host\n}",
        )
        with patch.object(system_info.sys, "platform", "darwin"), \
             patch.object(system_info, "_read_command", side_effect=outputs), \
             patch.object(system_info, "_system_zone", return_value="Asia/Taipei"), \
             patch.dict(os.environ, {"TZ": "Europe/Paris"}):
            result = system_info.read_system()
        self.assertEqual(result["region"], "TW")
        self.assertEqual(result["language"], "zh-Hans-HK")
        self.assertEqual(result["script"], "Hans")
        self.assertEqual(result["system_timezone"], "Asia/Taipei")
        self.assertEqual(result["terminal_timezone"], "Europe/Paris")
        self.assertIs(result["auto_timezone"], False)
        self.assertIs(result["proxy_enabled"], True)
        self.assertEqual(result["proxy_summary"], "HTTPS")

    def test_missing_macos_preferences_are_unknown(self):
        with patch.object(system_info.sys, "platform", "darwin"), \
             patch.object(system_info, "_read_command", return_value=None):
            result = system_info.read_system()
        for key in ("locale", "language", "region", "script", "auto_timezone", "proxy_enabled"):
            self.assertIsNone(result[key])

    def test_nonmac_skips_apple_preferences(self):
        with patch.object(system_info.sys, "platform", "linux"), \
             patch.object(system_info, "_read_command") as command, \
             patch.dict(os.environ, {"TZ": ""}):
            result = system_info.read_system()
        command.assert_not_called()
        self.assertEqual(result["terminal_timezone"], "UTC")
        self.assertIsNone(result["region"])

    def test_disabled_proxy_and_empty_zone_override(self):
        self.assertIs(system_info._proxy_state("<dictionary> {\n}")[0], False)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(system_info._terminal_zone("Asia/Taipei"), "Asia/Taipei")
