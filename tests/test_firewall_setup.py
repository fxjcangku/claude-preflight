import json
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from preflight import firewall_setup as setup


class ProfileIdentityTests(unittest.TestCase):
    def test_only_the_bundled_profile_identifier_and_uuid_match(self):
        for profile_id, uuid, expected in [
            ("some.other.profile", setup._PROFILE_UUID, False),
            (setup._PROFILE_ID, setup._PROFILE_UUID.lower(), True),
            (setup._PROFILE_ID, "ANOTHER-PROFILE", None),
        ]:
            payload = plistlib.dumps({"local_user": [{"ProfileIdentifier": profile_id, "ProfileUUID": uuid}]})
            with self.subTest(profile=profile_id), patch.object(
                    setup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, payload)):
                if expected is None:
                    with self.assertRaises(ValueError):
                        setup._profile_installed()
                else:
                    self.assertEqual(setup._profile_installed(), expected)


class FirewallSetupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / "private"
        self.record = self.folder / "firewall-setup.json"
        self.on = {"installed": True, "loaded": True, "running": True}
        self.off = dict.fromkeys(self.on, False)
        for obj, name, value in [
            (setup.sys, "platform", "darwin"),
            (setup, "_folder", self.folder),
            (setup, "_proxy_state", "ready"),
            (setup, "_profile_installed", False),
            (setup, "inspect_desktop_firewall", {"configuration_ready": True, "findings": []}),
            (setup.dock, "dock_watcher_status", self.on),
            (setup.dock, "install_dock_watcher", self.on),
            (setup.dock, "uninstall_dock_watcher", self.off),
            (setup.dock, "_candidate", None),
        ]:
            if name == "platform":
                mocked = patch.object(obj, name, value)
            else:
                mocked = patch.object(obj, name, return_value=value)
            setattr(self, name, mocked.start())
            self.addCleanup(mocked.stop)

    def test_preexisting_setup_is_preserved_and_restore_is_idempotent(self):
        self.assertEqual(setup.configure_firewall("status")["status"], "ok")
        self.assertFalse(self.folder.exists())
        self.assertEqual(setup.configure_firewall("apply")["status"], "ok")
        self.assertEqual(self.record.stat().st_mode & 0o777, 0o600)
        for _ in range(2):
            self.assertEqual(setup.configure_firewall("restore")["status"], "ok")
        self.uninstall_dock_watcher.assert_not_called()
        self.assertFalse(self.record.exists())

    def test_profile_and_watcher_added_by_wizard_require_explicit_profile_removal(self):
        self.dock_watcher_status.return_value = self.off
        self._proxy_state.return_value = "missing"
        pending = setup.configure_firewall("apply")
        self.assertEqual(pending["actionRequired"], "profile")
        self.assertTrue(Path(pending["openPath"]).is_file())
        self.install_dock_watcher.assert_not_called()
        self._proxy_state.return_value = "ready"
        self._profile_installed.return_value = True
        self.assertEqual(setup.configure_firewall("apply")["status"], "ok")
        self.dock_watcher_status.return_value = self.on
        self._candidate.return_value = (12, "start")
        self.assertEqual(setup.configure_firewall("restore")["actionRequired"], "quitClaude")
        self.uninstall_dock_watcher.assert_not_called()
        self._candidate.return_value = None
        self.assertEqual(setup.configure_firewall("restore")["actionRequired"], "removeProfile")
        self.uninstall_dock_watcher.assert_called_once()
        self._profile_installed.return_value = False
        self.assertEqual(setup.configure_firewall("restore")["status"], "ok")
        self.assertFalse(self.record.exists())
        self.uninstall_dock_watcher.assert_called_once()

    def test_lulu_conflict_and_failed_update_leave_manual_rules_intact(self):
        self.inspect_desktop_firewall.return_value = {"configuration_ready": False, "findings": []}
        self.assertEqual(setup.configure_firewall("apply")["actionRequired"], "lulu")
        self.install_dock_watcher.assert_not_called()
        self.inspect_desktop_firewall.return_value["configuration_ready"] = True
        self._proxy_state.return_value = "conflict"
        self.assertEqual(setup.configure_firewall("apply")["status"], "error")
        self.install_dock_watcher.assert_not_called()
        self._proxy_state.return_value = "ready"
        self.install_dock_watcher.side_effect = ValueError("请在当前 Claude 退出后更新")
        self.assertEqual(setup.configure_firewall("apply")["actionRequired"], "quitClaude")

    def test_unsafe_or_inconsistent_record_cannot_remove_anything(self):
        self.folder.mkdir(mode=0o700)
        self.record.write_text(json.dumps(dict.fromkeys(setup._KEYS, True)))
        self.record.chmod(0o600)
        self.assertEqual(setup.configure_firewall("restore")["status"], "error")
        self.uninstall_dock_watcher.assert_not_called()
        self.assertTrue(self.record.exists())
