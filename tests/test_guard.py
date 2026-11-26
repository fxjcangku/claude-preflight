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

    def test_health_or_ip_drift_latches_without_terminating_application(self):
        for local, remote in [(object(), "1.1.1.1"), ("same", "8.8.8.8"),
                              ("same", ValueError("unconfirmed"))]:
            latch, relay, stop = guard._Latch(), Mock(), threading.Event()
            latch.attach(relay)
            remote_mock = Mock(side_effect=remote) if isinstance(remote, Exception) else Mock(return_value=remote)
            with self.subTest(local=local, remote=remote), \
                 patch.object(guard, "_identity", return_value=local), \
                 patch.object(guard, "_trace_ip", remote_mock), \
                 patch.object(guard, "_LOCAL_INTERVAL", 0.005), \
                 patch.object(guard, "_IP_INTERVAL", 0.005), contextlib.redirect_stderr(io.StringIO()):
                try:
                    guard._watch(latch, stop, "same", "1.1.1.1", 30000)
                    self.assertTrue(latch.locked.wait(1))
                    relay.lock.assert_called_once()
                finally:
                    stop.set()

    def test_quick_remote_check_keeps_one_request(self):
        with patch.object(guard, "_trace_ip", return_value="baseline") as probe:
            guard._confirm_remote(31844, "baseline", threading.Event(), guard._Latch())
        probe.assert_called_once()
        self.assertEqual(probe.call_args.args, (31844,))

    def test_overlapping_probes_share_same_port_and_deadline_and_do_not_mask_drift(self):
        timeout = subprocess.CalledProcessError(28, ["curl"])
        tls_error = subprocess.CalledProcessError(60, ["curl"])
        # The first column is the slow primary outcome. The hedge completes first.
        for primary, backup, expected_error in (
            (timeout, "baseline", None),
            ("changed", "baseline", ValueError),
            (tls_error, "baseline", subprocess.CalledProcessError),
            ("baseline", "changed", ValueError),
            (timeout, timeout, subprocess.CalledProcessError),
            ("baseline", timeout, subprocess.CalledProcessError),
        ):
            with self.subTest(primary=primary, backup=backup):
                enqueued = threading.Event()
                first = threading.Event()
                primary_done = threading.Event()
                original_queue = guard.queue.Queue()
                original_put = original_queue.put
                def put(item):
                    original_put(item)
                    enqueued.set()
                original_queue.put = put

                def respond(port, deadline):
                    if not first.is_set():
                        first.set()
                        if not enqueued.wait(1):
                            raise RuntimeError("backup did not finish")
                        primary_done.set()
                        outcome = primary
                    else:
                        outcome = backup
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                with patch.object(guard.queue, "Queue", return_value=original_queue), \
                     patch.object(guard, "_TRACE_HEDGE_DELAY", 0.003), \
                     patch.object(guard, "_trace_ip", side_effect=respond) as probe:
                    result = self.assertRaises(expected_error) if expected_error else contextlib.nullcontext()
                    with result:
                        guard._confirm_remote(31022, "baseline", threading.Event(), guard._Latch())
                    self.assertTrue(primary_done.wait(1))
                    self.assertEqual(probe.call_count, 2)
                    self.assertEqual(probe.call_args_list[0], probe.call_args_list[1])
                    self.assertEqual(probe.call_args_list[0].args, (31022,))

    def test_failure_before_confirmation_closes_live_local_relay_without_waiting(self):
        stop = threading.Event()
        second_started, finish_backup = threading.Event(), threading.Event()
        counter = []
        def respond(port, deadline):
            counter.append(1)
            if len(counter) == 1:
                self.assertTrue(second_started.wait(1))
                raise subprocess.CalledProcessError(28, ["curl"])
            second_started.set()
            finish_backup.wait(2)
            return "baseline"

        with socket.socket() as upstream:
            upstream.bind(("127.0.0.1", 0))
            upstream.listen()
            upstream.settimeout(1)
            relay = guard.LockedRelay(upstream.getsockname()[1])
            latch = guard._Latch()
            latch.attach(relay)
            try:
                with socket.create_connection(("127.0.0.1", relay.port), timeout=1) as client:
                    client.sendall(b"CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai\r\n\r\n")
                    peer, _ = upstream.accept()
                    with peer:
                        self.assertIn(b"CONNECT claude.ai:443", peer.recv(1024))
                        peer.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        self.assertIn(b" 200 ", client.recv(1024))
                        with patch.object(guard, "_IP_INTERVAL", 0.003), \
                             patch.object(guard, "_LOCAL_INTERVAL", 10), \
                             patch.object(guard, "_TRACE_HEDGE_DELAY", 0.003), \
                             patch.object(guard, "_trace_ip", side_effect=respond), \
                             contextlib.redirect_stderr(io.StringIO()):
                            guard._watch(latch, stop, "same", "baseline", relay.port)
                            self.assertTrue(latch.locked.wait(1))
                            self.assertFalse(finish_backup.is_set())
                            self.assertEqual(client.recv(1), b"")
                            finish_backup.set()
                            self.assertTrue(latch.locked.is_set())
            finally:
                stop.set()
                finish_backup.set()
                relay.close()

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

    def test_hedged_check_never_extends_original_overall_deadline(self):
        release = threading.Event()
        def slow(*args, **kwargs):
            release.wait(1)
            return "baseline"
        try:
            with patch.object(guard, "_TRACE_SECONDS", 0.06), \
                 patch.object(guard, "_TRACE_HEDGE_DELAY", 0.012), \
                 patch.object(guard, "_trace_ip", side_effect=slow) as probe:
                begin = time.monotonic()
                with self.assertRaises(TimeoutError):
                    guard._confirm_remote(30912, "baseline", threading.Event(), guard._Latch())
                self.assertLess(time.monotonic() - begin, 0.4)
                self.assertEqual(probe.call_count, 2)
                self.assertEqual(probe.call_args_list[0], probe.call_args_list[1])
        finally:
            release.set()

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
