"""Launch native guarded sessions independently of the dashboard process."""

import contextlib
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import threading
import time


_ENTRYPOINT = Path(__file__).resolve().parent.parent / "claude-preflight"
_READY = b"READY\n"
_START_TIMEOUT = 60
_START_ERROR = "受管启动未通过，请检查环境检测结果和客户端保护设置。"
_TIMEOUT_ERROR = "等待受管客户端就绪超时，已取消启动。"


_ERRORS = {
    "SLOT_BUSY": "已有同类受管会话。请完全退出原客户端，再重新启动。",
    "CLIENT_OPEN": "Claude 桌面版已打开。请完全退出应用，再从面板启动。",
    "ENVIRONMENT": "地区或时区检查未通过。请在面板查看检测结果。",
    "PROXY": "无法确认 OneVPN 的代理、节点或网络出口。请检查连接后重试。",
    "DESKTOP_PROTECTION": "请检查 LuLu 防火墙规则和 Claude 桌面版固定代理设置。",
    "WEB_PROTECTION": "专用 Chrome 的代理保护检查未通过，请检查 Chrome 是否已安装并可启动。",
}
_MESSAGES = {f"ERROR {code}\n".encode("ascii"): message for code, message in _ERRORS.items()}
_MESSAGES[_READY] = None


class StartupFailure(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(detail or _ERRORS[code])
        self.code = code


def notify_dashboard(code=None):
    """Report a fixed startup outcome once, without forwarding raw diagnostics."""
    target = os.environ.pop("PREFLIGHT_READY_FD", "")
    if not target.isascii() or not target.isdecimal() or len(target) > 10:
        return
    fd = int(target)
    if not 2 < fd <= 0x7fffffff:
        return
    try:
        if stat.S_ISFIFO(os.fstat(fd).st_mode):
            if code is None:
                os.write(fd, _READY)
            elif code in _ERRORS:
                os.write(fd, f"ERROR {code}\n".encode("ascii"))
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _wait_ready(fd):
    deadline = time.monotonic() + _START_TIMEOUT
    data = bytearray()
    limit = max(map(len, _MESSAGES))
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(data) < limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError
            chunk = os.read(fd, limit - len(data))
            if not chunk:
                break
            data.extend(chunk)
            frame = bytes(data)
            if frame in _MESSAGES:
                return _MESSAGES[frame]
            if not any(message.startswith(frame) for message in _MESSAGES):
                break
    return _START_ERROR


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
                raise ValueError("这个客户端已在启动或运行中。如已锁网，请完全退出原客户端后重开。")
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
            error = _wait_ready(read_fd)
            ready = error is None
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
