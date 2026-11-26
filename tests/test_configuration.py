import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from preflight import configuration as config
from preflight.__main__ import main


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name) / "configuration"
        self.state = dict(locale="zh-Hans_HK", effectiveLocale="zh-Hans_HK", localeForced=False,
                          timezone="Asia/Hong_Kong", autoTimezone=True)
        for item in (patch.object(config, "_folder", return_value=self.folder),
                     patch.object(config, "_read", side_effect=lambda: dict(self.state)),
                     patch.object(config, "_write_locale", side_effect=self.write_locale)):
            item.start()
            self.addCleanup(item.stop)

    def write_locale(self, value):
        self.state.update(locale=value, effectiveLocale=value or "en_US")

    def apply_plan(self, result):
        for step in result["adminPlan"]:
            if step["operation"] == "setTimezone":
                self.state["timezone"] = step["timezone"]
            else:
                self.state["autoTimezone"] = step["enabled"]

    def test_status_no_write_apply_retry_verify_and_restore(self):
        start = dict(self.state)
        self.assertFalse(config.configure()["backupAvailable"])
        self.assertFalse(self.folder.exists())
        pending = config.configure("taiwan")
        self.assertFalse(pending["ok"])
        self.assertEqual(pending["actionRequired"], "admin")
        self.assertEqual(self.state["locale"], "zh-Hans_TW")
        self.assertEqual(pending["adminPlan"], [{"operation": "setAutomaticTimezone", "enabled": False},
                                                {"operation": "setTimezone", "timezone": "Asia/Taipei"}])
        self.assertIn("/usr/sbin/systemsetup -settimezone Asia/Taipei", pending["adminScript"])
        self.assertNotIn("sudo", pending["adminScript"])
        self.assertNotIn(str(self.folder), pending["adminScript"])
        path = self.folder / "original.json"
        saved = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)
        self.assertEqual(config.configure("taiwan", verify=True)["actionRequired"], "error")
        self.assertEqual(config.configure("taiwan")["adminPlan"], pending["adminPlan"])
        self.assertEqual(path.read_bytes(), saved)
        self.apply_plan(pending)
        self.assertTrue(config.configure("taiwan", verify=True)["configured"])
        restore = config.configure("restore")
        self.assertEqual(restore["adminPlan"], [{"operation":"setTimezone", "timezone": "Asia/Hong_Kong"},
                                                {"operation": "setAutomaticTimezone", "enabled": True}])
        self.assertEqual(config.configure("restore", verify=True)["actionRequired"], "error")
        self.assertEqual(path.read_bytes(), saved)
        self.apply_plan(restore)
        self.assertTrue(config.configure("restore", verify=True)["ok"])
        self.assertEqual(self.state, start)
        self.assertFalse(path.exists())

    def test_no_preference_is_restored_as_absence(self):
        self.state.update(locale=None, effectiveLocale="en_US", timezone="Asia/Taipei", autoTimezone=False)
        self.assertTrue(config.configure("taiwan")["ok"])
        self.assertEqual(config._backup(self.folder), {"locale": None})
        self.assertEqual(self.state["locale"], "en_TW")
        self.assertTrue(config.configure("restore")["ok"])
        self.assertIsNone(self.state["locale"])

    def test_existing_taiwan_settings_are_not_invented_as_changes(self):
        self.state.update(locale=None, effectiveLocale="zh-Hans_TW", timezone="Asia/Taipei", autoTimezone=False)
        result = config.configure("taiwan")
        self.assertTrue(result["configured"])
        self.assertFalse(result["backupAvailable"])
        self.assertFalse(config.configure("restore")["backupAvailable"])
        self.assertIsNone(self.state["locale"])

    def test_only_changed_keys_and_preserve_old_baseline(self):
        self.state.update(timezone="Asia/Taipei", autoTimezone=False)
        self.assertTrue(config.configure("taiwan")["ok"])
        self.assertEqual(config._backup(self.folder), {"locale": "zh-Hans_HK"})
        self.state["timezone"] = "Europe/Paris"
        self.assertEqual(config.configure("taiwan")["actionRequired"], "admin")
        self.assertEqual(config._backup(self.folder), {"locale": "zh-Hans_HK", "timezone": "Europe/Paris"})

    def test_locale_keywords_variants_language_and_script(self):
        for source, expected in [
            ("zh-Hant-HK", "zh-Hant-TW"), ("en_US_POSIX", "en_TW_POSIX"),
            ("ja_JP@calendar=japanese", "ja_TW@calendar=japanese"),
            ("en-u-hc-h23", "en_TW-u-hc-h23"), ("zh-Hans", "zh-Hans_TW"),
        ]:
            self.assertEqual(config._taiwan_locale(source), expected)

    def test_write_failure_preserves_backup_and_private_backup_required(self):
        with patch.object(config, "_write_locale", side_effect=OSError("private path")):
            result = config.configure("taiwan")
        self.assertEqual(result["actionRequired"], "error")
        self.assertNotIn("private path", result["message"])
        self.assertTrue(result["backupAvailable"])
        self.assertEqual(config._backup(self.folder), {"locale": self.state["locale"]})
        os.chmod(self.folder / "original.json", 0o644)
        self.assertEqual(config.configure("restore")["actionRequired"], "error")

    def test_managed_locale_refuses_change_without_backup(self):
        self.state["localeForced"] = True
        result = config.configure("taiwan")
        self.assertFalse(result["ok"])
        self.assertFalse(result["backupAvailable"])

    def test_cli_pending_remains_machine_readable(self):
        output = io.StringIO()
        with patch("sys.argv", ["claude-preflight", "configure", "--action", "taiwan", "--json"]), redirect_stdout(output):
            self.assertEqual(main(), 0)
        self.assertEqual(json.loads(output.getvalue())["actionRequired"], "admin")

    def test_restore_detects_user_modified_conflict_and_preserves_it(self):
        pending = config.configure("taiwan")
        self.apply_plan(pending)
        self.assertTrue(config.configure("taiwan", verify=True)["ok"])
        # User later changes timezone manually to Asia/Tokyo
        self.state["timezone"] = "Asia/Tokyo"
        restore = config.configure("restore")
        self.assertEqual(restore["actionRequired"], "admin")
        # Only autoTimezone should be restored; user's manual timezone is preserved
        self.assertEqual(restore["adminPlan"], [{"operation": "setAutomaticTimezone", "enabled": True}])
        self.assertTrue(restore["conflicts"])
        self.apply_plan(restore)
        done = config.configure("restore", verify=True)
        self.assertTrue(done["ok"])
        self.assertEqual(self.state["timezone"], "Asia/Tokyo")
        self.assertEqual(self.state["locale"], "zh-Hans_HK")
        self.assertTrue(done["conflicts"])


if __name__ == "__main__":
    unittest.main()
