import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from preflight import chrome_web


class ChromeWebSettingsTests(unittest.TestCase):
    def language_home(self, source_intl, target_intl=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        home = Path(directory.name)
        for mocked in (patch.object(Path, "home", return_value=home),
                       patch.object(chrome_web.os, "access", return_value=True)):
            mocked.start()
            self.addCleanup(mocked.stop)
        support = home / "Library" / "Application Support"
        root = support / "Google" / "Chrome"
        source = root / "Profile 2" / "Preferences"
        source.parent.mkdir(parents=True)
        (root / "Local State").write_text(json.dumps({"profile": {"last_used": "Profile 2"}}))
        source.write_text(json.dumps({"intl": source_intl, "unrelated_source": True}))
        target = support / "Claude Preflight" / "Guarded Chrome" / "Default" / "Preferences"
        if target_intl is not None:
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"intl": target_intl, "unrelated_target": 4}))
        return source, target

    @unittest.skipUnless(sys.platform == "darwin", "reads native Chrome preferences with plutil")
    def test_first_launch_inherits_selected_profile_languages_only(self):
        langs = {"accept_languages": "zh-Hans-TW,zh-Hans,zh", "selected_languages": "zh-Hans-TW,zh"}
        source, target = self.language_home(langs)
        unchanged = source.read_bytes()
        command = chrome_web.web_command(12345)
        self.assertIn("--profile-directory=Default", command)
        self.assertEqual(json.loads(target.read_text()), {"intl": langs})
        self.assertEqual(source.read_bytes(), unchanged)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(sys.platform == "darwin", "reads native Chrome preferences with plutil")
    def test_migration_leaves_other_settings_intact_and_respects_singleton(self):
        _, target = self.language_home({"accept_languages": "zh-Hans-TW,zh-Hans,zh"},
                                       {"accept_languages": "zh-CN,zh", "other": "preserve"})
        lock = target.parent.parent / "SingletonLock"
        lock.symlink_to("already-running")
        unchanged = target.read_bytes()
        with self.assertRaises(ValueError):
            chrome_web.web_command(12345)
        self.assertEqual(target.read_bytes(), unchanged)
        lock.unlink()
        chrome_web.web_command(12345)
        expected = {"accept_languages": "zh-Hans-TW,zh-Hans,zh",
                    "selected_languages": "zh-Hans-TW,zh-Hans,zh", "other": "preserve"}
        self.assertEqual(json.loads(target.read_text()), {"intl": expected, "unrelated_target": 4})

    @unittest.skipUnless(sys.platform == "darwin", "reads native Chrome preferences with plutil")
    def test_dedicated_custom_languages_are_kept(self):
        _, target = self.language_home({"accept_languages": "en-GB,en"},
                                       {"accept_languages": "zh-CN,zh", "selected_languages": "fr-CA,fr"})
        unchanged = target.read_bytes()
        chrome_web.web_command(12345)
        self.assertEqual(target.read_bytes(), unchanged)

    def test_invalid_language_lists_are_rejected(self):
        for value in ("en-GB\r\nX-Header", "zh-CN;q=0.8", "en,,fr", "中文", "en-a", "x/y"):
            with self.subTest(value=value):
                self.assertIsNone(chrome_web._language_list(value))

    def test_owner_only_dedicated_session(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(Path, "home", return_value=Path(temp)), \
                patch.object(chrome_web.os, "access", return_value=True):
            support = Path(temp) / "Library" / "Application Support"
            support.mkdir(parents=True)
            command = chrome_web.web_command(12345)
            profile = support / "Claude Preflight" / "Guarded Chrome"
            self.assertEqual(profile.stat().st_mode & 0o777, 0o700)
            self.assertIn(f"--user-data-dir={profile}", command)
            self.assertIn("--proxy-server=http://127.0.0.1:12345", command)
            self.assertIn("--proxy-bypass-list=<-loopback>", command)
            self.assertIn("--disable-quic", command)
            self.assertIn("--disable-extensions", command)
            self.assertIn("--force-webrtc-ip-handling-policy=disable_non_proxied_udp", command)
            self.assertNotIn("--no-sandbox", command)
            (profile / "SingletonLock").symlink_to(profile / "missing-owner")
            with self.assertRaises(ValueError):
                chrome_web.web_command(12345)

    def test_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(Path, "home", return_value=Path(temp)):
            support = Path(temp) / "Library" / "Application Support"
            support.mkdir(parents=True)
            target = Path(temp) / "unrelated"
            target.mkdir(mode=0o755)
            (support / "Claude Preflight").symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError):
                chrome_web.web_command(12345)
            self.assertEqual(list(target.iterdir()), [])


@unittest.skipUnless(os.access(chrome_web._CHROME, os.X_OK), "real macOS Google Chrome not installed")
class ChromeProxyIntegrationTests(unittest.TestCase):
    def test_same_browser_loses_local_proxy_without_direct_fallback(self):
        self.assertIsNone(chrome_web.verify_chrome_proxy())

    def test_precheck_rejects_an_explicit_direct_fallback(self):
        secure_options = chrome_web._options

        def insecure_options(port, profile):
            return [option + ",direct://" if option.startswith("--proxy-server=") else option
                    for option in secure_options(port, profile)]

        with patch.object(chrome_web, "_options", side_effect=insecure_options):
            with self.assertRaisesRegex(ValueError, "断线验证"):
                chrome_web.verify_chrome_proxy()


if __name__ == "__main__":
    unittest.main()
