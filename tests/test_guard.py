import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from preflight import guard


_TCP = "tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 131072 131072 OneVPNCore:1007 00000"
_TUN = ("kctl 0 0 40 20 8388608 524288 OneVPNCore:1007 00182 00000000 0 00008000 "
        "00000000 1 0 000000 9 5 com.apple.net.utun_control")
_SCUTIL = "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : 127.0.0.1\n  HTTPSPort : 7890\n}"


def selection(first="route", second="sample", current="test"):
    return json.dumps({"currentProfileId": current, "profiles": [
        {"id": current, "selectedMap": {"Proxies": first, "route": second}}
    ]})


class GuardTests(unittest.TestCase):
    def test_current_profile_or_selected_node_changes_even_with_same_exit(self):
        baseline = guard._selection_digest(selection())
        self.assertEqual(len(baseline), 32)
        for values in [dict(first="direct"), dict(second="other"), dict(current="another")]:
            self.assertNotEqual(guard._selection_digest(selection(**values)), baseline)
        for raw in ("not-json", "{}", selection(first="Proxies"), selection(second="")):
            with self.assertRaisesRegex(ValueError, "无法确认"):
                guard._selection_digest(raw)

    def test_expected_system_evidence(self):
        processes = [(10, os.getuid(), "start", guard._GUI),
                     (1007, 0, "start", str(Path.home() / "Library/Application Support/OneVPN/OneVPNCore"))]
        with patch.object(guard, "_processes", return_value=processes), \
             patch.object(guard, "_output", side_effect=[
                 _SCUTIL, _TCP, _TUN, "utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500",
                 selection()
             ]):
            found = guard._identity()
            self.assertEqual((found.core[0], found.port, found.tunnels), (1007, 7890, (8,)))

    def test_reject_uncertain_guard_ownership(self):
        for value in (_SCUTIL.replace("127.0.0.1", "localhost"), _SCUTIL.replace("7890", "0"),
                      _SCUTIL.replace("HTTPSEnable", "HTTPEnable"),
                      _SCUTIL.replace("\n}", "\n  ProxyAutoConfigEnable : 1\n}"),
                      _SCUTIL.replace("  HTTPSProxy", "    HTTPSProxy")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                guard._proxy_port(value)
        for line in (_TCP.replace("1007", "2000"), _TCP.replace("OneVPNCore", "Other"),
                     _TCP.replace("127.0.0.1.7890", "*.7890"), _TCP + "\n" + _TCP):
            with self.subTest(line=line), self.assertRaises(ValueError):
                guard._verify_listener(line, 7890, 1007)
        with self.assertRaises(ValueError):
            guard._tunnels(_TUN.replace("OneVPNCore:1007", "Other:1007"), 1007)
        with patch.object(guard, "_processes", return_value=[]), self.assertRaises(ValueError):
            guard._identity()

    def test_macos27_restricted_netstat_corroboration_and_squatter_rejection(self):
        processes = [(10, os.getuid(), "start", guard._GUI),
                     (1007, 0, "start", str(Path.home() / "Library/Application Support/OneVPN/OneVPNCore"))]
        sys_text = (
            "a9e7 stream 0 0 0 8318 0 0 1 1 8192 8192 OneVPN:10 00102 /tmp/OneVPNSocket.sock\n"
            "8318 stream 0 0 0 a9e7 0 0 1 1 8192 8192 OneVPNCore:1007 00182\n"
            "       5       29        9   524288   524288 com.apple.net.utun_control \n"
        )
        ifconfig_all = (
            "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n"
            "\tinet6 fe80::1%utun0 prefixlen 64\n"
            "utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000\n"
            "\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc\n"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            scutil = _SCUTIL.replace("7890", str(port))
            cfg = {"mixed-port": port, "tun": {"enable": True}}
            with patch.object(guard, "_processes", return_value=processes), \
                 patch.object(guard, "_onevpn_runtime_config", return_value=cfg), \
                 patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "")), \
                 patch.object(guard, "_output", side_effect=[
                     scutil, "", sys_text, ifconfig_all,
                     "utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000", selection()
                 ]):
                found = guard._identity()
                self.assertEqual((found.core[0], found.port, found.tunnels), (1007, port, (8,)))

            # If a non-root user process is squatting on the port (lsof non-empty), reject!
            with patch.object(guard, "_onevpn_runtime_config", return_value=cfg), \
                 patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "python 999 user TCP 127.0.0.1:7890 (LISTEN)")):
                with self.assertRaisesRegex(ValueError, "非特权进程"):
                    guard._verify_listener_restricted(sys_text, port, 10, 1007)

            # If IPC socket pair does not match OneVPN:10 <-> OneVPNCore:1007, reject!
            with self.assertRaisesRegex(ValueError, "活跃通信连接"):
                guard._verify_ipc_pair(sys_text.replace("OneVPNCore:1007", "Other:1007"), 10, 1007)

    def test_trace_and_child_pin_proxy_without_inherited_bypass(self):
        env = {"hTTps_PrOxy": "malformed", "HTTP_PROXY": "other", "No_Proxy": "*",
               "ALL_PROXY": "other", "SAFE": "preserved"}
        response = subprocess.CompletedProcess([], 0, b"h=claude.ai\nip=1.1.1.1\nloc=TW\n\n200")
        with patch.dict(os.environ, env, clear=True):
            child = guard._environment(30991)
            self.assertEqual(child["HTTPS_PROXY"], "http://127.0.0.1:30991")
            self.assertEqual(child["NO_PROXY"], "")
            self.assertNotIn("No_Proxy", child)
            self.assertEqual(child["SAFE"], "preserved")
            with patch.object(subprocess, "run", return_value=response) as run:
                self.assertEqual(guard._trace_ip(30991), "1.1.1.1")
                args = run.call_args.args[0]
                self.assertEqual(args[-1], "https://claude.ai/cdn-cgi/trace")
                self.assertEqual(args[args.index("--proxy") + 1], child["HTTPS_PROXY"])
                self.assertEqual(args[args.index("--noproxy") + 1], "")
                self.assertFalse(any("proxy" in k.lower() for k in run.call_args.kwargs["env"]))

    def test_unreadable_trace_or_non_success_status(self):
        for body in (b"h=claude.ai\nip=1.1.1.1\nloc=TW\n\n302",
                     b"h=other.example\nip=1.1.1.1\nloc=TW\n\n200"):
            response = subprocess.CompletedProcess([], 0, body)
            with patch.object(subprocess, "run", return_value=response), self.assertRaises(ValueError):
                guard._trace_ip(32100)

    @unittest.skipUnless(sys.platform == "darwin" and os.access(guard._SANDBOX, os.X_OK),
                         "macOS sandbox-exec required")
    def test_socket_fence_against_two_loopback_listeners(self):
        with socket.socket() as own:
            own.bind(("127.0.0.1", 0))
            own.listen(1)
            port = own.getsockname()[1]
            guard._verify_sandbox(guard._sandbox_profile(port), port)
            with self.assertRaises(ValueError):
                guard._verify_sandbox("(version 1)(allow default)", port)

    def test_manual_lock_waits_for_relay_and_remains_latched(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(guard, "_registry", return_value=Path(folder)), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(guard.lock_sessions(), (0, 0))
            latch = guard._Latch()
            relay = Mock()
            latch.attach(relay)
            with guard._control(latch):
                self.assertEqual(guard.lock_sessions(), (1, 0))
                relay.lock.assert_called_once()
                self.assertTrue(latch.locked.is_set())
                self.assertEqual(guard.lock_sessions(), (1, 0))
                relay.lock.assert_called_once()
            self.assertEqual(guard.lock_sessions(), (0, 0))

    def test_stale_socket_is_never_acknowledged(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(guard, "_registry", return_value=Path(folder)):
            path = Path(folder) / "stale.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
                endpoint.bind(str(path))
            self.assertEqual(guard.lock_sessions(), (0, 1))
            self.assertFalse(path.exists())

    def test_lock_received_during_startup_refuses_attach(self):
        with contextlib.redirect_stderr(io.StringIO()):
            latch = guard._Latch()
            latch.lock("测试")
            relay = Mock()
            with self.assertRaises(ValueError):
                latch.attach(relay)
            relay.lock.assert_called_once()

    def test_local_or_confirmed_exit_drift_permanently_locks(self):
        for local, remote in [("changed", "baseline"), ("same", "other")]:
            stop = threading.Event()
            latch, relay = guard._Latch(), Mock()
            latch.attach(relay)
            with self.subTest(local=local, remote=remote), \
                 patch.object(guard, "_identity", return_value=local), \
                 patch.object(guard, "_trace_ip", return_value=remote), \
                 patch.object(guard, "_LOCAL_INTERVAL", 0.005), \
                 patch.object(guard, "_IP_INTERVAL", 0.005), contextlib.redirect_stderr(io.StringIO()):
                try:
                    guard._watch(latch, stop, "same", "baseline", 30000)
                    self.assertTrue(latch.locked.wait(1))
                    relay.lock.assert_called_once()
                    relay.activate.assert_not_called()
                finally:
                    stop.set()

    def test_unknown_exit_pauses_then_only_fresh_upstream_confirmation_resumes(self):
        baseline = guard._Identity((), (), 7890, (8,), b"node")
        relay = Mock()
        resumed = threading.Event()
        relay.activate.side_effect = resumed.set
        latch, stop = guard._Latch(), threading.Event()
        latch.attach(relay)
        order = []
        outcomes = iter([subprocess.CalledProcessError(28, ["curl"]), ValueError("no trace"), "original"])
        def probe(port, deadline):
            order.append(port)
            result = next(outcomes)
            if isinstance(result, Exception):
                raise result
            return result
        def identity():
            order.append("local")
            return baseline
        def pause():
            order.append("paused")
        relay.pause.side_effect = pause

        with patch.object(guard, "_LOCAL_INTERVAL", 10), patch.object(guard, "_IP_INTERVAL", .025), \
             patch.object(guard, "_RETRY_DELAYS", (.005, .01)), patch.object(guard, "_identity", side_effect=identity), \
             patch.object(guard, "_trace_ip", side_effect=probe), contextlib.redirect_stderr(io.StringIO()):
            try:
                guard._watch(latch, stop, baseline, "original", 31777)
                self.assertTrue(resumed.wait(1))
                self.assertEqual(order, [31777, "paused", "local", 7890, "local", 7890, "local"])
                self.assertFalse(latch.locked.is_set())
                relay.pause.assert_called_once()
                relay.activate.assert_called_once()
            finally:
                stop.set()

    def test_recovery_cannot_revive_after_manual_local_or_exit_change(self):
        baseline = guard._Identity((), (), 7890, (8,), b"node")
        for reason in ("manual", "exit", "before-local", "after-local", "local-during-probe"):
            with self.subTest(reason=reason):
                relay, stop, latch = Mock(), threading.Event(), guard._Latch()
                latch.attach(relay)
                recovering, finish, done = threading.Event(), threading.Event(), threading.Event()
                ports, checks = [], []
                def probe(port, deadline):
                    ports.append(port)
                    if len(ports) == 1:
                        raise TimeoutError()
                    recovering.set()
                    finish.wait(2)
                    done.set()
                    return "changed" if reason == "exit" else "original"
                def identity():
                    checks.append(1)
                    if (reason == "before-local" or reason == "after-local" and len(checks) == 2
                            or reason == "local-during-probe" and recovering.is_set()):
                        return object()
                    return baseline

                local_interval = 0.005 if reason == "local-during-probe" else 10
                with patch.object(guard, "_LOCAL_INTERVAL", local_interval), patch.object(guard, "_IP_INTERVAL", .002), \
                     patch.object(guard, "_RETRY_DELAYS", (.002,)), patch.object(guard, "_identity", side_effect=identity), \
                     patch.object(guard, "_trace_ip", side_effect=probe), contextlib.redirect_stderr(io.StringIO()):
                    try:
                        guard._watch(latch, stop, baseline, "original", 31555)
                        if reason != "before-local":
                            self.assertTrue(recovering.wait(1))
                        if reason == "manual":
                            latch.lock("manual")
                        if reason == "local-during-probe":
                            self.assertTrue(latch.locked.wait(1))
                        finish.set()
                        self.assertTrue(latch.locked.wait(1))
                        self.assertEqual(ports, [31555] if reason == "before-local" else [31555, 7890])
                        if reason != "before-local":
                            self.assertTrue(done.wait(1))
                        self.assertFalse(latch.resume(stop))
                        relay.activate.assert_not_called()
                        relay.lock.assert_called_once()
                    finally:
                        finish.set()
                        stop.set()

    def test_manual_or_local_lock_is_independent_of_inflight_remote_check(self):
        for source in ("manual", "local"):
            stop, started, finish = threading.Event(), threading.Event(), threading.Event()
            latch, relay = guard._Latch(), Mock()
            latch.attach(relay)
            def pending(*args, **kwargs):
                started.set()
                finish.wait(1)
                return "baseline"
            def local():
                return "changed" if source == "local" and started.is_set() else "original"
            with self.subTest(source=source), patch.object(guard, "_IP_INTERVAL", 0.003), \
                 patch.object(guard, "_LOCAL_INTERVAL", 0.005), \
                 patch.object(guard, "_trace_ip", side_effect=pending), \
                 patch.object(guard, "_identity", side_effect=local), \
                 contextlib.redirect_stderr(io.StringIO()):
                try:
                    guard._watch(latch, stop, "original", "baseline", 31548)
                    self.assertTrue(started.wait(1))
                    if source == "manual":
                        latch.lock("manual test")
                    self.assertTrue(latch.locked.wait(0.3))
                    self.assertFalse(finish.is_set())
                    relay.lock.assert_called_once()
                finally:
                    stop.set()
                    finish.set()

    def test_runtime_deadline_and_late_mismatch_still_lock(self):
        release = threading.Event()
        latch = guard._Latch()
        latch.attach(Mock())
        def slow(*args, **kwargs):
            release.wait(1)
            return "changed"
        try:
            with patch.object(guard, "_TRACE_SECONDS", 0.04), \
                 patch.object(guard, "_trace_ip", side_effect=slow), contextlib.redirect_stderr(io.StringIO()):
                begin = time.monotonic()
                with self.assertRaises(TimeoutError):
                    guard._confirm_remote(30912, "baseline", threading.Event(), latch)
                self.assertLess(time.monotonic() - begin, 0.4)
                release.set()
                self.assertTrue(latch.locked.wait(1))
        finally:
            release.set()

    def test_busy_slot_reports_safe_reason_before_starting_client(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(guard, "_registry", return_value=Path(tmp)), \
             patch.object(guard.sys, "platform", "darwin"), patch.object(guard.fcntl, "flock", side_effect=BlockingIOError()), \
             patch.object(guard.stat, "S_ISSOCK", return_value=False), patch.object(guard, "_supervise") as launch, \
             patch.object(guard, "notify_dashboard") as notify, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(guard.run_guard([], "1.1.1.1", client="desktop"), 2)
            notify.assert_called_once_with("SLOT_BUSY")
            launch.assert_not_called()

    def test_desktop_and_web_refuse_handoff_or_option_overrides(self):
        with patch.object(guard, "_processes", return_value=[(122, 500, "start", guard._DESKTOP)]):
            with self.assertRaisesRegex(ValueError, "完全退出"):
                guard._command("desktop", [], 31000)
        with self.assertRaisesRegex(ValueError, "额外启动参数"):
            guard._command("web", ["--proxy-server=other"], 31234)
        with self.assertRaisesRegex(ValueError, "--desktop"):
            guard._command("cli", ["--desktop"], 31234)

    @unittest.skipUnless(sys.platform == "darwin" and os.access(guard._SANDBOX, os.X_OK),
                         "macOS sandbox-exec required")
    def test_fake_terminal_client_survives_acknowledged_lock_and_keeps_job_group(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as upstream:
            folder = Path(tmp)
            upstream.bind(("127.0.0.1", 0))
            upstream.listen(1)
            ident = guard._Identity((), (), upstream.getsockname()[1], (8,), b"test")
            started, ack = folder / "started", folder / "acked"
            code = (
                "import os,pathlib,sys,time\n"
                "started, ack = map(pathlib.Path,sys.argv[1:3])\n"
                "assert os.getpgrp() == int(sys.argv[3])\n"
                "assert os.environ['HTTPS_PROXY'].startswith('http://127.0.0.1:')\n"
                "started.touch()\n"
                "for _ in range(300):\n"
                " if ack.exists(): sys.exit(0)\n"
                " time.sleep(.02)\n"
                "sys.exit(19)\n"
            )
            command = [sys.executable, "-I", "-S", "-c", code, str(started), str(ack), str(os.getpgrp())]
            replies = []
            def manual_lock():
                deadline = time.monotonic() + 5
                while not started.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                replies.append(guard.lock_sessions())
                ack.touch()
            with patch.object(guard, "_identity", return_value=ident), \
                 patch.object(guard, "_trace_ip", return_value="1.1.1.1"), \
                 patch.object(guard, "_command", return_value=command), \
                 patch.object(guard, "_registry", return_value=folder), \
                 contextlib.redirect_stderr(io.StringIO()):
                worker = threading.Thread(target=manual_lock, daemon=True)
                worker.start()
                result = guard.run_guard([], "1.1.1.1")
                worker.join(timeout=7)
                self.assertEqual(result, 0)
                self.assertEqual(replies, [(1, 0)])
                self.assertEqual(guard.lock_sessions(), (0, 0))

    def test_web_uses_chrome_probe_and_fails_closed(self):
        from preflight import chrome_web
        ident = guard._Identity((), (), 7890, (8,), b"test")
        with patch.object(guard, "_identity", return_value=ident), \
             patch.object(guard, "LockedRelay") as relay, \
             patch.object(chrome_web, "verify_chrome_proxy", side_effect=ValueError("incompatible")), \
             patch.object(guard, "_verify_sandbox") as outer_sandbox, \
             patch.object(subprocess, "Popen") as launch:
            relay.return_value.port = 31234
            with self.assertRaisesRegex(ValueError, "incompatible"):
                guard._supervise([], "web", "1.1.1.1", guard._Latch())
            outer_sandbox.assert_not_called()
            launch.assert_not_called()
            relay.return_value.close.assert_called_once()

    def test_startup_drift_never_launches_a_client(self):
        ident = guard._Identity((), (), 7890, (8,), b"test")
        with patch.object(guard, "_identity", return_value=ident), \
             patch.object(guard, "LockedRelay") as relay, patch.object(guard, "_verify_sandbox"), \
             patch.object(guard, "_trace_ip", return_value="8.8.8.8"), \
             patch.object(subprocess, "Popen") as launch, self.assertRaises(ValueError):
            relay.return_value.port = 31000
            try:
                guard._supervise([], "cli", "1.1.1.1", guard._Latch())
            finally:
                relay.return_value.close.assert_called_once()
                launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
