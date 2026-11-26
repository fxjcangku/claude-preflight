"""Watch for a native Claude opened by the current macOS user."""
import contextlib
import fcntl
import hashlib
import io
import json
import os
import plistlib
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from .guard import _DESKTOP, _client_slot, _private_dir, _processes, _registry


_LABEL = "io.github.fxjcangku.claude-preflight.dock"
_SOURCE = Path(__file__).resolve().parent.parent
_BUNDLED = getattr(__loader__, "archive", None)
_ENTRY = Path(_BUNDLED).resolve() if _BUNDLED else _SOURCE / "claude-preflight"
_MODULES = ("__init__", "__main__", "core", "system_info", "network", "guard",
            "relay", "native_firewall", "dock")
_START_ENV = "PREFLIGHT_DESKTOP_START"


def _require_user():
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("Dock 监听器需要当前登录的普通 macOS 用户")


def _atomic_write(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".preflight-", delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def _candidate():
    candidates = [(pid, start) for pid, uid, start, command in _processes()
                  if uid == os.getuid() and command == _DESKTOP]
    return candidates[0] if len(candidates) == 1 else None


def _attempt(candidate, marker):
    if candidate is None:
        return None
    identity = json.dumps(candidate, ensure_ascii=True).encode("ascii")
    try:
        previous = json.loads(marker.read_bytes())
        if (not isinstance(previous, list) or len(previous) != 2
                or type(previous[0]) is not int or not isinstance(previous[1], str)):
            raise ValueError("Dock 锁定记录格式无效，已停止接管")
        if tuple(previous) == candidate:
            return None
    except FileNotFoundError:
        pass
    # Commit before spawning: lock, failure, watcher restart and launch-agent
    # reload must never resume network access for the same app instance.
    _atomic_write(marker, identity)
    try:
        with _client_slot("desktop"):
            pass
    except ValueError:
        return None
    pid, start = candidate
    env = dict(os.environ, **{_START_ENV: start})
    # The child takes its own desktop slot for the entire attachment. Its
    # independent check of the supplied start time closes the PID-reuse race.
    return subprocess.Popen(
        [sys.executable, str(_ENTRY), "attach-desktop", str(pid)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env, close_fds=True,
    )


def watch_dock():
    """One low-frequency process-table check when no attached child is running."""
    _require_user()
    directory = _registry()
    stop = threading.Event()
    ready = directory / "dock-agent.pid"
    child = None
    lock_fd = os.open(directory / "dock-agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("当前用户已有 Dock 监听器") from None
        previous = {s: signal.signal(s, lambda *_: stop.set())
                    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        try:
            _atomic_write(ready, str(os.getpid()).encode("ascii"))
            while not stop.is_set():
                if child is None or child.poll() is not None:
                    child = None
                    try:
                        child = _attempt(_candidate(), directory / "dock-attempt.json")
                    except (OSError, subprocess.SubprocessError):
                        # Transient inspection failure does not clear the app instance marker.
                        pass
                stop.wait(2)
        finally:
            ready.unlink(missing_ok=True)
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            if child is not None and child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        child.kill()
                    child.wait()
    return 0


def _agent_path():
    return Path.home() / "Library" / "LaunchAgents" / (_LABEL + ".plist")


def _runtime_dir():
    return Path.home() / "Library" / "Application Support" / "Claude Preflight" / "runtime"


def _deploy_runtime():
    """Create a byte-verified, private zipapp with only the watch/attach code."""
    if _BUNDLED:
        return _ENTRY
    folder = _runtime_dir()
    _private_dir(folder.parent)
    _private_dir(folder)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name in _MODULES:
            item = f"preflight/{name}.py"
            data = (_SOURCE / item).read_bytes()
            compile(data, item, "exec")
            bundle.writestr(zipfile.ZipInfo(item), data)
        bundle.writestr(zipfile.ZipInfo("__main__.py"), _ENTRY.read_bytes())
    payload = buffer.getvalue()
    digest = hashlib.sha256(payload).hexdigest()
    entry = folder / f"preflight-{digest}.pyz"
    if entry.is_symlink():
        raise ValueError("Dock 运行时文件存在异常链接")
    if not entry.exists() or entry.read_bytes() != payload:
        _atomic_write(entry, payload)
    if hashlib.sha256(entry.read_bytes()).hexdigest() != digest:
        raise ValueError("Dock 运行时文件校验失败")
    check = subprocess.run([sys.executable, str(entry), "--help"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6)
    if check.returncode:
        raise ValueError("无法执行已安装的 Dock 运行时")
    return entry


def _agent_config(entry):
    return {
        "Label": _LABEL,
        "ProgramArguments": [sys.executable, str(entry), "watch-desktop"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 15,
        "LimitLoadToSessionType": "Aqua",
        "ProcessType": "Background",
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }


def _launchctl(*args):
    return subprocess.run(["/bin/launchctl", *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=10)


def _domain():
    return "gui/" + str(os.getuid())


def dock_watcher_status():
    """Report registration and a handshake from this user's live watcher."""
    _require_user()
    path = _agent_path()
    listed = _launchctl("print", _domain() + "/" + _LABEL)
    match = re.search(r"^\s*pid = (\d+)\s*$", listed.stdout, re.MULTILINE)
    ready = False
    if listed.returncode == 0 and match:
        try:
            ready = (_registry() / "dock-agent.pid").read_text().strip() == match[1]
        except OSError:
            pass
    return {"installed": path.is_file(), "loaded": listed.returncode == 0, "running": ready}


def _managed_config(path):
    if path.is_symlink():
        raise ValueError("同名启动项是符号链接，无法确认归属")
    if not path.exists():
        return None
    try:
        existing = plistlib.loads(path.read_bytes())
        python, entry, command = existing["ProgramArguments"]
        entry = Path(entry)
        ours = (entry == _ENTRY or
                entry.parent == _runtime_dir() and re.fullmatch(r"preflight-[a-f0-9]{64}\.pyz", entry.name))
        expected = _agent_config(entry)
        expected["ProgramArguments"][0] = python
        if (not isinstance(python, str) or not Path(python).is_absolute()
                or command != "watch-desktop" or not ours or existing != expected):
            raise ValueError
        return existing
    except (KeyError, TypeError, OSError, ValueError, plistlib.InvalidFileException):
        raise ValueError("无法确认已有同名启动项由本项目管理") from None


@contextlib.contextmanager
def _installation_lock():
    fd = os.open(_registry() / "dock-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _bootout():
    # launchctl may return before the job is no longer registered. A bootstrap
    # in that interval can see the old job and leave the new plist unloaded.
    response = _launchctl("bootout", _domain() + "/" + _LABEL)
    for _ in range(50):
        if not dock_watcher_status()["loaded"]:
            return
        time.sleep(0.15)
    raise ValueError(f"原 Dock 监听服务尚未注销（launchctl {response.returncode}）")


def _ensure_running(path, state):
    deadline = time.monotonic() + 18
    retry_at = 0
    last_code = None
    while not state["running"] and time.monotonic() < deadline:
        now = time.monotonic()
        if not state["loaded"] and now >= retry_at:
            last_code = _launchctl("bootstrap", _domain(), str(path)).returncode
            retry_at = now + 1
        time.sleep(0.2)
        state = dock_watcher_status()
    if state["running"]:
        return state
    if not state["loaded"]:
        raise ValueError(f"Dock 监听服务未能在当前用户会话中注册（launchctl {last_code}）")
    raise ValueError("Dock 启动项已注册，但其用户进程尚未完成就绪握手")


def install_dock_watcher():
    """Serialize updates and wait for the new user's live handshake."""
    _require_user()
    with _installation_lock():
        return _install_watcher()


def _install_watcher():
    path = _agent_path()
    previous = _managed_config(path)
    state = dock_watcher_status()
    if state["loaded"] and previous is None:
        raise ValueError("同名服务缺少本项目安装文件，无法确认归属")
    entry = _deploy_runtime()
    config = _agent_config(entry)
    if previous != config:
        if state["running"] and _candidate() is not None:
            raise ValueError("请在当前 Claude 退出后更新 Dock 监听器，避免中断活动保护")
        if state["loaded"]:
            _bootout()
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, plistlib.dumps(config))
        state = dock_watcher_status()
    return _ensure_running(path, state)


def uninstall_dock_watcher():
    """Remove this user's agent and only the dedicated deployment archives."""
    _require_user()
    with _installation_lock():
        return _uninstall_watcher()


def _uninstall_watcher():
    path = _agent_path()
    previous = _managed_config(path)
    if dock_watcher_status()["loaded"]:
        if previous is None:
            raise ValueError("同名服务缺少本项目安装文件，无法确认归属")
        _bootout()
    path.unlink(missing_ok=True)
    folder = _runtime_dir()
    if folder.is_dir() and not folder.is_symlink():
        for entry in folder.iterdir():
            if re.fullmatch(r"preflight-[a-f0-9]{64}\.pyz", entry.name) and entry.is_file():
                entry.unlink()
        if not any(folder.iterdir()):
            folder.rmdir()
    return dock_watcher_status()
