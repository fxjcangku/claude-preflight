import contextlib
import hashlib
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from preflight import dock


class DockWatcherTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        registry = patch.object(dock, "_registry", return_value=Path(directory.name))
        registry.start()
        self.addCleanup(registry.stop)

    def test_only_exact_unique_current_user_native_app(self):
        main = (21, 501, "first launch", dock._DESKTOP)
        rows = [main, (31, 502, "other login", dock._DESKTOP),
                (32, 501, "helper", dock._DESKTOP + " Helper")]
        with patch.object(dock.os, "getuid", return_value=501):
            with patch.object(dock, "_processes", return_value=rows):
                self.assertEqual(dock._candidate(), (21, "first launch"))
            with patch.object(dock, "_processes", return_value=rows + [(22, *main[1:])]):
                self.assertIsNone(dock._candidate())
            with patch.object(dock, "_processes", return_value=rows[1:]):
                self.assertIsNone(dock._candidate())

    def test_locked_or_previously_attempted_pid_never_reattaches(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "attempt.json"
            with patch.object(dock, "_client_slot", return_value=contextlib.nullcontext()), \
                 patch.object(dock.subprocess, "Popen") as spawn:
                child = dock._attempt((42, "first"), marker)
                self.assertIs(child, spawn.return_value)
                args, kwargs = spawn.call_args
                self.assertEqual(args[0], [sys.executable, str(dock._ENTRY), "attach-desktop", "42"])
                self.assertEqual(kwargs["env"]["PREFLIGHT_DESKTOP_START"], "first")
                self.assertIsNone(dock._attempt(None, marker))
                self.assertIsNone(dock._attempt((42, "first"), marker))
                self.assertEqual(spawn.call_count, 1)
                dock._attempt((42, "next"), marker)
                self.assertEqual(spawn.call_count, 2)

    def test_slot_held_or_child_launch_failure_remains_latched(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(dock.subprocess, "Popen") as spawn:
            mark = Path(tmp) / "attempt.json"
            with patch.object(dock, "_client_slot", side_effect=ValueError("already managed")):
                self.assertIsNone(dock._attempt((80, "start"), mark))
            with patch.object(dock, "_client_slot", return_value=contextlib.nullcontext()):
                self.assertIsNone(dock._attempt((80, "start"), mark))
                spawn.assert_not_called()
                spawn.side_effect = OSError("launch unavailable")
                with self.assertRaises(OSError):
                    dock._attempt((81, "restart"), mark)
                self.assertIsNone(dock._attempt((81, "restart"), mark))
            self.assertEqual(spawn.call_count, 1)

    def test_installer_targets_current_gui_domain_and_waits_for_handshake(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "LaunchAgents" / "agent.plist"
            initial = {"installed": True, "loaded": False, "running": False}
            ready = {"installed": True, "loaded": True, "running": True}
            entry = Path(tmp) / "runtime" / "entry.pyz"
            with patch.object(dock, "_require_user"), patch.object(dock, "_agent_path", return_value=target), \
                 patch.object(dock, "_deploy_runtime", return_value=entry), \
                 patch.object(dock, "_domain", return_value="gui/501"), \
                 patch.object(dock, "dock_watcher_status", side_effect=[initial, initial, ready]), \
                 patch.object(dock, "_launchctl", return_value=Mock(returncode=0)) as ctl:
                self.assertEqual(dock.install_dock_watcher(), ready)
            config = plistlib.loads(target.read_bytes())
            self.assertEqual(config["ProgramArguments"], [sys.executable, str(entry), "watch-desktop"])
            self.assertEqual(config["StandardErrorPath"], "/dev/null")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            ctl.assert_called_once_with("bootstrap", "gui/501", str(target))
            self.assertNotIn("UserName", config)

    def test_deployment_is_private_deterministic_and_excludes_user_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Claude Preflight" / "runtime"
            with patch.object(dock, "_runtime_dir", return_value=folder):
                first = dock._deploy_runtime()
                stamp = first.stat().st_mtime_ns
                self.assertEqual(dock._deploy_runtime(), first)
                self.assertEqual(first.stat().st_mtime_ns, stamp)
            self.assertEqual(first.stem, "preflight-" + hashlib.sha256(first.read_bytes()).hexdigest())
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            with zipfile.ZipFile(first) as archive:
                expected = {"preflight/" + name + ".py" for name in dock._MODULES}
                self.assertEqual(set(archive.namelist()), expected | {"__main__.py"})
            command = [sys.executable, str(first), "--help"]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertIn("attach-desktop", result.stdout)

    def test_install_migrates_our_previous_checkout_agent_without_touching_other_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            path = folder / "agent.plist"
            path.write_bytes(plistlib.dumps(dock._agent_config(dock._ENTRY)))
            new = folder / "runtime" / ("preflight-" + "a" * 64 + ".pyz")
            previous = {"installed": True, "loaded": True, "running": False}
            stopped = {"installed": True, "loaded": False, "running": False}
            ready = {"installed": True, "loaded": True, "running": True}
            with patch.object(dock, "_require_user"), patch.object(dock, "_agent_path", return_value=path), \
                 patch.object(dock, "_deploy_runtime", return_value=new), \
                 patch.object(dock, "_bootout") as stop, \
                 patch.object(dock, "dock_watcher_status", side_effect=[previous, stopped, ready]), \
                 patch.object(dock, "_launchctl", return_value=Mock(returncode=0)):
                self.assertEqual(dock.install_dock_watcher(), ready)
                stop.assert_called_once()
            self.assertEqual(plistlib.loads(path.read_bytes()), dock._agent_config(new))

    def test_bootout_waits_for_actual_deregistration(self):
        shutting_down = {"installed": True, "loaded": True, "running": False}
        stopped = {"installed": True, "loaded": False, "running": False}
        with patch.object(dock, "_launchctl", return_value=Mock(returncode=0)) as ctl, \
             patch.object(dock, "dock_watcher_status", side_effect=[shutting_down, shutting_down, stopped]), \
             patch.object(dock.time, "sleep") as wait:
            dock._bootout()
        ctl.assert_called_once()
        self.assertEqual(wait.call_count, 2)

    def test_registration_lost_while_waiting_is_retried_and_handshake_is_required(self):
        stale = {"installed": True, "loaded": True, "running": False}
        absent = {"installed": True, "loaded": False, "running": False}
        ready = {"installed": True, "loaded": True, "running": True}
        times = [10.0]
        def advance(delay):
            times[0] += delay
        checks = [absent] * 8 + [stale, ready]
        with patch.object(dock.time, "monotonic", side_effect=lambda: times[0]), \
             patch.object(dock.time, "sleep", side_effect=advance), \
             patch.object(dock, "dock_watcher_status", side_effect=checks), \
             patch.object(dock, "_launchctl", side_effect=[Mock(returncode=5), Mock(returncode=0)]) as ctl:
            self.assertEqual(dock._ensure_running(Path("/my/agent.plist"), stale), ready)
        self.assertEqual(ctl.call_count, 2)

    def test_idempotent_install_does_not_restart_a_healthy_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            path = folder / "agent.plist"
            entry = folder / ("preflight-" + "1" * 64 + ".pyz")
            path.write_bytes(plistlib.dumps(dock._agent_config(entry)))
            ready = {"installed": True, "loaded": True, "running": True}
            with patch.object(dock, "_require_user"), patch.object(dock, "_agent_path", return_value=path), \
                 patch.object(dock, "_runtime_dir", return_value=folder), \
                 patch.object(dock, "_deploy_runtime", return_value=entry), \
                 patch.object(dock, "dock_watcher_status", return_value=ready), \
                 patch.object(dock, "_launchctl") as ctl:
                self.assertEqual(dock.install_dock_watcher(), ready)
            ctl.assert_not_called()

    def test_status_requires_matching_live_agent_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            marker = folder / "dock-agent.pid"
            listing = subprocess.CompletedProcess([], 0, stdout="state = running\n\tpid = 400\n")
            with patch.object(dock, "_require_user"), patch.object(dock, "_registry", return_value=folder), \
                 patch.object(dock, "_launchctl", return_value=listing):
                marker.write_text("399")
                self.assertFalse(dock.dock_watcher_status()["running"])
                marker.write_text("400")
                self.assertTrue(dock.dock_watcher_status()["running"])
