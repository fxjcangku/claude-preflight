import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from preflight import desktop_launch


class LocalLaunchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.script = self.folder / "fake-client"
        patched = patch.object(desktop_launch, "_ENTRYPOINT", self.script)
        patched.start()
        self.addCleanup(patched.stop)
        self.launches = desktop_launch.LocalLaunches()

    def await_state(self, client, expected):
        end = time.monotonic() + 4
        while time.monotonic() < end:
            row = self.launches.status()[client]
            if row["state"] == expected:
                return row
            time.sleep(0.01)
        self.fail(f"{client} never reached {expected}: {self.launches.status()[client]}")

    def test_ready_gate_and_finished_session(self):
        self.script.write_text(
            "import os,sys,time,json\nfrom pathlib import Path\n"
            "Path('args').write_text(json.dumps(sys.argv[1:]))\n"
            "while not Path('permit').exists(): time.sleep(.01)\n"
            "fd = int(os.environ['PREFLIGHT_READY_FD']); os.write(fd,b'READY\\n'); os.close(fd)\n"
            "while not Path('finish').exists(): time.sleep(.01)\n"
        )
        self.assertEqual(self.launches.launch("web")["web"]["state"], "starting")
        with self.assertRaises(ValueError):
            self.launches.launch("web")
        (self.folder / "permit").touch()
        try:
            self.await_state("web", "running")
            self.assertEqual(json.loads((self.folder / "args").read_text()), ["run", "--client", "web"])
            self.assertEqual(self.launches.status()["desktop"]["state"], "idle")
            with self.assertRaises(ValueError):
                self.launches.launch("web")
        finally:
            (self.folder / "finish").touch()
        self.assertIsNone(self.await_state("web", "ended")["error"])

    def test_missing_or_invalid_handshake_never_exposes_stderr(self):
        self.script.write_text(
            "import os,sys\nprint('dummy secret diagnostic',file=sys.stderr)\n"
            "os.write(int(os.environ['PREFLIGHT_READY_FD']), b'wrong')\n"
        )
        self.launches.launch("desktop")
        result = self.await_state("desktop", "failed")
        self.assertNotIn("dummy", str(result))
        self.assertNotIn("wrong", str(result))
        self.script.write_text("pass\n")
        self.launches.launch("desktop")
        self.await_state("desktop", "failed")

    def test_only_complete_allowlisted_errors_reach_dashboard(self):
        for frame, expected in [
            (b"ERROR SLOT_BUSY\n", desktop_launch._ERRORS["SLOT_BUSY"]),
            (b"ERROR PROXY\n", desktop_launch._ERRORS["PROXY"]),
            (b"ERROR SLOT_BUSY private details\n", desktop_launch._START_ERROR),
            (b"ERROR UNKNOWN\n", desktop_launch._START_ERROR),
            (b"ERROR SLOT_BUSY", desktop_launch._START_ERROR),
        ]:
            with self.subTest(frame=frame):
                self.script.write_text(
                    "import os\n"
                    "fd=int(os.environ['PREFLIGHT_READY_FD'])\n"
                    "os.write(fd,b'ER')\n"
                    f"os.write(fd,{frame[2:]!r})\n"
                )
                self.launches.launch("web")
                self.assertEqual(self.await_state("web", "failed")["error"], expected)

    def test_child_sends_only_allowlisted_outcome_and_closes_pipe(self):
        for code, frame in [(None, b"READY\n"), ("SLOT_BUSY", b"ERROR SLOT_BUSY\n"),
                            ("private details", b"")]:
            with self.subTest(code=code):
                read_fd, write_fd = os.pipe()
                try:
                    with patch.dict(os.environ, PREFLIGHT_READY_FD=str(write_fd)):
                        desktop_launch.notify_dashboard(code)
                        desktop_launch.notify_dashboard("PROXY")
                        self.assertNotIn("PREFLIGHT_READY_FD", os.environ)
                    self.assertEqual(os.read(read_fd, 128), frame)
                    self.assertEqual(os.read(read_fd, 1), b"")
                finally:
                    os.close(read_fd)

    def test_handshake_deadline_cancels_only_the_unready_launcher(self):
        self.script.write_text("import time\ntime.sleep(20)\n")
        with patch.object(desktop_launch, "_START_TIMEOUT", .2):
            self.launches.launch("desktop")
            self.assertIn("超时", self.await_state("desktop", "failed")["error"])

    def test_manual_lock_cancels_a_launch_before_guard_registration(self):
        self.script.write_text("import time\ntime.sleep(20)\n")
        self.launches.launch("web")
        self.assertEqual(self.launches.cancel_starting(), 1)
        self.assertIn("锁定", self.await_state("web", "failed")["error"])

    def test_invalid_clients_and_state_copy(self):
        for client in ("cli", "--help", ["web"], {}, None):
            with self.subTest(client=client), self.assertRaises(ValueError):
                self.launches.launch(client)
        self.launches.status()["web"]["state"] = "running"
        self.assertEqual(self.launches.status()["web"]["state"], "idle")


if __name__ == "__main__":
    unittest.main()
