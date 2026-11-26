"""Launch native guarded sessions independently of the dashboard process."""

import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time


_ENTRYPOINT = Path(__file__).resolve().parent.parent / "claude-preflight"
_READY = b"READY\n"
_START_TIMEOUT = 60
_START_ERROR = "受管启动未通过，请检查环境检测结果和客户端保护设置。"
_TIMEOUT_ERROR = "等待受管客户端就绪超时，已取消启动。"


def _wait_ready(fd):
    deadline = time.monotonic() + _START_TIMEOUT
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(data) < len(_READY):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError
            chunk = os.read(fd, len(_READY) - len(data))
            if not chunk:
                return False
            data.extend(chunk)
            if not _READY.startswith(data):
                return False
    return True


def _cancel_launch(proc):
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class LocalLaunches:
    """Track the current or last launch of each GUI client from this server."""

    def __init__(self):
        self._guard = threading.Lock()
        self._pending = {}
        self._states = {name: {"state": "idle", "error": None} for name in ("web", "desktop")}

    def _snapshot(self):
        return {name: dict(state) for name, state in self._states.items()}

    def status(self):
        with self._guard:
            return self._snapshot()

    def launch(self, client):
        if not isinstance(client, str) or client not in ("web", "desktop"):
            raise ValueError("请选择专用网页或 Claude 桌面版")
        with self._guard:
            if self._states[client]["state"] in ("starting", "running"):
                raise ValueError("这个客户端已在启动或运行中")
            read_fd = write_fd = None
            proc = None
            try:
                read_fd, write_fd = os.pipe()
                proc = subprocess.Popen(
                    [sys.executable, str(_ENTRYPOINT), "run", "--client", client],
                    cwd=_ENTRYPOINT.parent,
                    env=dict(os.environ, PREFLIGHT_READY_FD=str(write_fd)),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True, pass_fds=(write_fd,), start_new_session=True,
                )
                cancelled = threading.Event()
                self._pending[client] = (proc, cancelled)
                thread = threading.Thread(target=self._observe, args=(client, proc, read_fd, cancelled),
                                          name=f"preflight-launch-{client}", daemon=True)
                self._states[client] = {"state": "starting", "error": None}
                thread.start()
                read_fd = None  # The observer owns this descriptor now.
            except (OSError, RuntimeError):
                self._pending.pop(client, None)
                if proc is not None:
                    _cancel_launch(proc)
                self._states[client] = {"state": "failed", "error": _START_ERROR}
            finally:
                if write_fd is not None:
                    os.close(write_fd)
                if read_fd is not None:
                    os.close(read_fd)
            return self._snapshot()

    def cancel_starting(self):
        """Stop launches that have not yet reported a usable protected session."""
        with self._guard:
            pending = tuple(self._pending.values())
            for _, cancelled in pending:
                cancelled.set()
        for proc, _ in pending:
            _cancel_launch(proc)
        return len(pending)

    def _observe(self, client, proc, read_fd, cancelled):
        ready = False
        error = _START_ERROR
        try:
            ready = _wait_ready(read_fd)
        except TimeoutError:
            error = _TIMEOUT_ERROR
        except OSError:
            pass
        finally:
            os.close(read_fd)
        with self._guard:
            self._pending.pop(client, None)
            if cancelled.is_set():
                ready = False
                error = "已按锁定请求取消此次启动。"
            if ready:
                self._states[client] = {"state": "running", "error": None}
        if not ready:
            _cancel_launch(proc)
            state = {"state": "failed", "error": error}
        else:
            if proc.wait() == 0:
                state = {"state": "ended", "error": None}
            else:
                state = {"state": "failed", "error": "受管会话已结束，客户端退出时出现异常。"}
        with self._guard:
            self._states[client] = state
