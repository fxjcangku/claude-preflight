import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from preflight import chrome_web


class ChromeWebSettingsTests(unittest.TestCase):
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
