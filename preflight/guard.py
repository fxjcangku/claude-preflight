"""A per-launch macOS socket fence and latching OneVPN relay.

A successful manual lock closes relay connections before acknowledging. The
process and its terminal stay alive. Remote IP changes are sampled, so a proxy
can change its exit between samples. This supervises newly launched clients,
not pre-existing processes, other applications or external system services.
"""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import queue
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .desktop_launch import StartupFailure, notify_dashboard
from .network import _trace
from .relay import LockedRelay


_GUARDED_HOST = "claude.ai"
_GUARDED_ENDPOINT = f"https://{_GUARDED_HOST}/cdn-cgi/trace"
_SANDBOX = "/usr/bin/sandbox-exec"
_GUI = "/Applications/OneVPN.app/Contents/MacOS/OneVPN"
_DESKTOP = "/Applications/Claude.app/Contents/MacOS/Claude"
DESKTOP_PORT = 47836
_LOCAL_INTERVAL = 0.8
_IP_INTERVAL = 4.0
_TRACE_SECONDS = 4
_STARTUP_TRACE_SECONDS = 8
_RETRY_DELAYS = (2, 4, 8)
_ENV = {"LC_ALL": "C", "PATH": os.defpath}


def _output(args):
    return subprocess.run(args, env=_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, check=True, timeout=2).stdout


def _processes():
    data = _output(["/bin/ps", "-axww", "-o", "pid=,uid=,lstart=,comm="])
    found = []
    for line in data.splitlines():
        fields = line.split(None, 7)
        if len(fields) == 8 and fields[0].isdigit() and fields[1].isdigit():
            found.append((int(fields[0]), int(fields[1]), " ".join(fields[2:7]), fields[7]))
    return found


def _proxy_port(output):
    # Only top-level keys. Scoped overrides and arrays inside the dictionary
    # cannot provide evidence of the active system HTTPS proxy.
    fields = dict(re.findall(r"^  (\w+)\s*:\s*(\S+)\s*$", output, re.M))
    if (fields.get("HTTPSEnable") != "1" or fields.get("HTTPSProxy") != "127.0.0.1"
            or fields.get("ProxyAutoConfigEnable") == "1"
            or fields.get("ProxyAutoDiscoveryEnable") == "1"):
        raise ValueError("需要 OneVPN 的系统 HTTPS 代理（127.0.0.1）")
    value = fields.get("HTTPSPort", "")
    if not value.isascii() or not value.isdigit() or not 0 < int(value) <= 65535:
        raise ValueError("无法确认 OneVPN 代理端口")
    return int(value)


def _verify_listener(text, port, core_pid):
    # A wildcard listener on the same port also makes ownership ambiguous.
    owners = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp4", "tcp46", "tcp6") or fields[5] != "LISTEN":
            continue
        if fields[3] in (f"127.0.0.1.{port}", f"*.{port}", f"::.{port}"):
            owners.append((fields[3], fields[10] if len(fields) > 10 else ""))
    if owners != [(f"127.0.0.1.{port}", f"OneVPNCore:{core_pid}")]:
        raise ValueError("未确认本地 HTTPS 监听端口由当前 OneVPNCore 独占")


def _tunnels(text, core_pid):
    units = []
    for line in text.splitlines():
        fields = line.split()
        if (len(fields) >= 11 and fields[0] == "kctl" and fields[-1] == "com.apple.net.utun_control"
                and fields[7] == f"OneVPNCore:{core_pid}" and fields[-3].isdigit()
                and int(fields[-3]) > 0):
            units.append(int(fields[-3]) - 1)
    if not units:
        raise ValueError("无法确认 OneVPNCore 拥有活动的 utun 控制连接")
    return tuple(sorted(set(units)))


def _selection_digest(raw):
    # Keep profile identifiers, node names and unrelated preferences private.
    # Follow nested selected groups, so changing their active selection also
    # invalidates the identity when the parent remains set to the same group.
    try:
        prefs = json.loads(raw)
        current = prefs["currentProfileId"]
        profiles = prefs["profiles"]
        if not isinstance(current, str) or not current or not isinstance(profiles, list):
            raise ValueError()
        active, = [p for p in profiles if isinstance(p, dict) and p.get("id") == current]
        selections = active["selectedMap"]
        if not isinstance(selections, dict) or "Proxies" not in selections:
            raise ValueError()
        group = "Proxies"
        visited = set()
        chain = [current]
        while group in selections:
            if group in visited:
                raise ValueError()
            visited.add(group)
            group = selections[group]
            if not isinstance(group, str) or not group.strip():
                raise ValueError()
            chain.append(group)
        return hashlib.sha256(json.dumps(chain, ensure_ascii=True).encode("ascii")).digest()
    except (KeyError, TypeError, ValueError, RecursionError):
        # Never include the source contents or exception in diagnostics.
        raise ValueError("无法确认 OneVPN 当前配置和所选节点") from None


@dataclass(frozen=True)
class _Identity:
    gui: tuple
    core: tuple
    port: int
    tunnels: tuple
    selection_digest: bytes
    system_zone: str = ""


def _onevpn_runtime_config():
    path = Path.home() / "Library/Application Support/OneVPN/config.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("未找到 OneVPN 运行时配置文件")
    info = path.stat()
    if info.st_uid != os.getuid():
        raise ValueError("OneVPN 运行时配置文件所有者异常")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("OneVPN 运行时配置格式无效")
    return data


def _verify_ipc_pair(system_text, gui_pid, core_pid):
    """Verify OneVPN GUI and root OneVPNCore share an active local UNIX socket pair."""
    gui_tag = f"OneVPN:{gui_pid}"
    core_tag = f"OneVPNCore:{core_pid}"
    gui_peers = {}
    core_addrs = set()
    for line in system_text.splitlines():
        if gui_tag not in line and core_tag not in line:
            continue
        fields = line.split()
        if len(fields) < 12 or fields[1] != "stream":
            continue
        addr, conn = fields[0], fields[5]
        if gui_tag in fields:
            gui_peers[addr] = conn
        if core_tag in fields:
            core_addrs.add(addr)
    if not any(conn in core_addrs for conn in gui_peers.values()):
        raise ValueError("未确认 OneVPN 界面与当前 OneVPNCore 的活跃通信连接")


def _verify_listener_restricted(system_text, port, gui_pid, core_pid):
    """Corroborate root OneVPNCore listener when macOS 27 hides TCP PCB tables from non-root."""
    _verify_ipc_pair(system_text, gui_pid, core_pid)
    cfg = _onevpn_runtime_config()
    configured_ports = {cfg.get("mixed-port"), cfg.get("port")}
    if port not in configured_ports:
        raise ValueError("系统代理端口与 OneVPN 运行时监听端口不一致")
    # Ensure no non-root user process is squatting on this loopback port.
    probe = subprocess.run(
        ["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
        env=_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, timeout=2, check=False,
    )
    if probe.stdout.strip():
        raise ValueError("检测到非特权进程占用本地代理端口，无法确认由 OneVPNCore 独占")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        if sock.connect_ex(("127.0.0.1", port)) != 0:
            raise ValueError("本地 HTTPS 代理端口未处于监听状态")


def _tunnels_restricted(system_text, gui_pid, core_pid):
    """Identify active IPv4 utun interface when macOS 27 redacts kctl owners in netstat."""
    if "com.apple.net.utun_control" not in system_text:
        raise ValueError("无法确认系统存在活动的 utun 控制连接")
    _verify_ipc_pair(system_text, gui_pid, core_pid)
    cfg = _onevpn_runtime_config()
    tun = cfg.get("tun")
    if not isinstance(tun, dict) or tun.get("enable") is not True:
        raise ValueError("OneVPN 运行时未启用 TUN 隧道")
    ifconfig = _output(["/sbin/ifconfig"])
    units = []
    current = None
    up_running = False
    has_ipv4 = False
    for line in ifconfig.splitlines():
        if not line.startswith(("\t", " ")):
            if current is not None and up_running and has_ipv4:
                units.append(current)
            match = re.match(r"^utun(\d+):\s*flags=\w+<([^>]+)>", line)
            if match:
                current = int(match.group(1))
                flags = set(match.group(2).split(","))
                up_running = {"UP", "RUNNING"}.issubset(flags)
                has_ipv4 = False
            else:
                current = None
                up_running = False
                has_ipv4 = False
        elif current is not None:
            stripped = line.strip()
            if stripped.startswith("inet ") and not stripped.startswith("inet 127."):
                has_ipv4 = True
    if current is not None and up_running and has_ipv4:
        units.append(current)
    if not units:
        raise ValueError("无法确认 OneVPN 活动的 IPv4 utun 隧道接口")
    return tuple(sorted(set(units)))


def _identity():
    table = _processes()
    core_path = str(Path.home() / "Library/Application Support/OneVPN/OneVPNCore")
    gui = [p for p in table if p[3] == _GUI and p[1] == os.getuid()]
    core = [p for p in table if p[3] == core_path and p[1] == 0]
    if len(gui) != 1 or len(core) != 1:
        raise ValueError("未找到可唯一确认的 OneVPN 界面和 root 核心进程")
    port = _proxy_port(_output(["/usr/sbin/scutil", "--proxy"]))
    tcp_text = _output(["/usr/sbin/netstat", "-anv", "-p", "tcp"])
    sys_text = _output(["/usr/sbin/netstat", "-anv", "-f", "system"])
    if tcp_text.strip():
        _verify_listener(tcp_text, port, core[0][0])
    else:
        _verify_listener_restricted(sys_text, port, gui[0][0], core[0][0])
    try:
        tunnels = _tunnels(sys_text, core[0][0])
    except ValueError:
        if "kctl" not in sys_text and "com.apple.net.utun_control" in sys_text:
            tunnels = _tunnels_restricted(sys_text, gui[0][0], core[0][0])
        else:
            raise
    for number in tunnels:
        name = f"utun{number}"
        link = _output(["/sbin/ifconfig", name]).splitlines()
        flags = re.match(re.escape(name) + r": flags=\w+<([^>]+)>", link[0] if link else "")
        if not flags or not {"UP", "RUNNING"}.issubset(flags[1].split(",")):
            raise ValueError("OneVPN 隧道接口未就绪")
    choice = _selection_digest(_output(["/usr/bin/defaults", "read", "top.proxy101.onevpn", "flutter.config"]))
    return _Identity(gui[0], core[0], port, tunnels, choice, os.path.realpath("/etc/localtime"))


def _trace_via_port(port, seconds=_STARTUP_TRACE_SECONDS, connect_timeout=5):
    # Explicit CONNECT through the exact relay used by the client. No proxy
    # environment, curlrc, redirects, credentials or provider API are involved.
    result = subprocess.run([
        "/usr/bin/curl", "-q", "--silent", "--proto", "=https", "--noproxy", "",
        "--proxy", f"http://127.0.0.1:{port}", "--connect-timeout", str(min(connect_timeout, seconds)),
        "--max-time", str(seconds),
        "--max-filesize", "16384", "--write-out", "\n%{http_code}", _GUARDED_ENDPOINT
    ], stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=seconds + 1, env=_ENV)
    body, sep, status = result.stdout.rpartition(b"\n")
    if not sep or status != b"200":
        raise ValueError("无法确认受管通道的出口 IP")
    return _trace(body, _GUARDED_HOST)


def _trace_ip(port, deadline=None):
    if deadline is None:
        return _trace_via_port(port)[1]
    # Round down to curl's millisecond granularity, never to zero (unlimited).
    millis = int((deadline - time.monotonic()) * 1000)
    if millis < 1:
        raise TimeoutError("受管探测已到截止时间")
    return _trace_via_port(port, millis / 1000, connect_timeout=2)[1]


def probe_guarded_network():
    """Obtain the first launch observation through a verified OneVPN listener."""
    try:
        expected = _identity()
        started = time.monotonic()
        country, address = _trace_via_port(expected.port)
        elapsed = round((time.monotonic() - started) * 1000)
        if _identity() != expected:
            raise ValueError("检测期间 OneVPN 状态已变化，已停止启动")
    except ValueError as exc:
        raise StartupFailure("PROXY", str(exc)) from None
    except (OSError, subprocess.SubprocessError):
        raise StartupFailure("PROXY") from None
    return dict(country=country, ip=address, latency_ms=elapsed, http_status=200,
                endpoint=_GUARDED_ENDPOINT, route="已核验的 OneVPN 本机代理", error=None)


def _sandbox_profile(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("无效的本地中继端口")
    return f'(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp4 "localhost:{port}"))'


def _verify_sandbox(profile, port):
    # Both test listeners exist. ECONNREFUSED would not prove denial.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other:
        other.bind(("127.0.0.1", 0))
        other.listen(1)
        script = (
            "import errno,socket,sys\n"
            "def connect(port):\n"
            " with socket.socket() as s:\n"
            "  s.settimeout(1); return s.connect_ex(('127.0.0.1',int(port)))\n"
            "sys.exit(0 if connect(sys.argv[1]) == 0 and connect(sys.argv[2]) "
            "in (errno.EACCES,errno.EPERM) else 1)"
        )
        probe = subprocess.run([_SANDBOX, "-p", profile, sys.executable, "-I", "-S", "-c",
                                script, str(port), str(other.getsockname()[1])],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, close_fds=True, timeout=4)
        if probe.returncode:
            raise ValueError("本机沙盒未通过允许中继、拒绝其他端口的实测")


def _environment(port):
    keys = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy"}
    env = {k: v for k, v in os.environ.items() if k.lower() not in keys}
    address = f"http://127.0.0.1:{port}"
    for key in ("http_proxy", "https_proxy", "all_proxy"):
        env[key] = env[key.upper()] = address
    env["no_proxy"] = env["NO_PROXY"] = ""
    return env


def _private_dir(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("控制目录权限不安全，已拒绝启动")
    return path


def _registry():
    return _private_dir(Path("/private/tmp") / f"preflight-guard-{os.getuid()}")


@contextlib.contextmanager
def _registry_lock(folder):
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        deadline = time.monotonic() + 8
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("控制服务正忙，未能确认锁定状态")
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


class _Latch:
    def __init__(self):
        self.mutex = threading.Lock()
        self.locked = threading.Event()
        self.relay = None

    def attach(self, relay):
        with self.mutex:
            self.relay = relay
            if self.locked.is_set():
                relay.lock()
                raise ValueError("启动期间已收到锁定请求")

    def resume(self, stop):
        with self.mutex:
            if self.locked.is_set() or stop.is_set():
                return False
            self.relay.activate()
            return True

    def lock(self, reason):
        with self.mutex:
            if self.locked.is_set():
                return
            if self.relay is not None:
                self.relay.lock()
            self.locked.set()
            print("Preflight 已锁定此会话的网络：" + reason, file=sys.stderr, flush=True)


def _read_message(peer):
    data = bytearray()
    while len(data) < 24 and not data.endswith(b"\n"):
        part = peer.recv(24 - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


@contextlib.contextmanager
def _control(latch):
    folder = _registry()
    path = folder / (secrets.token_hex(12) + ".sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stop = threading.Event()
    def accept():
        while not stop.is_set():
            try:
                peer, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with peer:
                try:
                    peer.settimeout(0.8)
                    if _read_message(peer) == b"LOCK\n":
                        latch.lock("已收到切换前的锁定请求")
                        peer.sendall(b"LOCKED\n")
                except OSError:
                    continue
    worker = threading.Thread(target=accept, daemon=True)
    bound = False
    try:
        with _registry_lock(folder):
            server.bind(str(path))
            bound = True
            path.chmod(0o600)
            server.listen(16)
            server.settimeout(.25)
            worker.start()
        yield
    finally:
        stop.set()
        server.close()
        if worker.ident is not None:
            worker.join(timeout=1.2)
        if bound:
            path.unlink(missing_ok=True)


def lock_sessions():
    """Latch currently registered sessions, returning (confirmed, unconfirmed)."""
    count = 0
    errors = 0
    try:
        folder = _registry()
        with _registry_lock(folder):
            for path in folder.glob("*.sock"):
                try:
                    info = path.lstat()
                    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                        raise ValueError("控制套接字所有者不匹配")
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                        peer.settimeout(3)
                        peer.connect(str(path))
                        peer.sendall(b"LOCK\n")
                        if _read_message(peer) != b"LOCKED\n":
                            raise ValueError("受管会话没有确认锁定")
                        count += 1
                except FileNotFoundError:
                    # The session exited and removed its server.
                    continue
                except ConnectionRefusedError:
                    errors += 1
                    path.unlink(missing_ok=True)
                except (OSError, ValueError):
                    errors += 1
    except (OSError, ValueError) as exc:
        print(f"Preflight：{exc}", file=sys.stderr)
        errors += 1
    return count, errors


def lock_guards():
    count, errors = lock_sessions()
    print(f"已确认 {count} 个受管会话锁定网络。" if count else "当前没有已确认锁定的受管会话。")
    if errors:
        print(f"{errors} 个控制端点无法确认，请先退出对应客户端。", file=sys.stderr)
    return 2 if errors else 0


def _confirm_remote(port, expected, stop, latch):
    """Only a fresh, timely observation can authorize forwarding."""
    deadline = time.monotonic() + _TRACE_SECONDS
    results = queue.Queue(maxsize=1)

    def probe():
        try:
            address = _trace_ip(port, deadline=deadline)
            if address != expected and not stop.is_set():
                # A positive drift result still counts if curl finishes late.
                latch.lock("已确认受管通道的出口 IP 变化")
            results.put(None)
        except Exception as exc:
            results.put(exc)

    threading.Thread(target=probe, name="preflight-trace", daemon=True).start()
    try:
        error = results.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        raise TimeoutError("未能在探测期限内确认出口") from None
    if time.monotonic() >= deadline:
        raise TimeoutError("未能在探测期限内确认出口")
    if error is not None:
        raise error


def _watch(latch, stop, baseline, expected, port):
    def local_ok():
        try:
            if _identity() == baseline:
                return True
        except Exception:
            pass
        latch.lock("OneVPN 节点、代理、隧道或系统时区变化，或状态无法确认")
        return False

    def watch_local():
        while not stop.wait(_LOCAL_INTERVAL) and not latch.locked.is_set():
            if not local_ok():
                return

    def watch_remote():
        retries = 0
        while not stop.is_set() and not latch.locked.is_set():
            delay = _RETRY_DELAYS[min(retries - 1, len(_RETRY_DELAYS) - 1)] if retries else _IP_INTERVAL
            if stop.wait(delay) or latch.locked.is_set():
                return
            if retries and not local_ok():
                return
            try:
                # The paused relay rejects all clients. Only this diagnostic
                # may use the original, independently revalidated upstream.
                _confirm_remote(baseline.port if retries else port, expected, stop, latch)
            except (OSError, ValueError, subprocess.SubprocessError):
                if not retries:
                    latch.relay.pause()
                retries = min(retries + 1, len(_RETRY_DELAYS))
                continue
            if stop.is_set() or latch.locked.is_set():
                return
            if retries:
                if not local_ok() or not latch.resume(stop):
                    return
                retries = 0

    def supervise_remote():
        try:
            watch_remote()
        except Exception:
            latch.lock("监护程序无法继续核验受管网络")

    for observer in (watch_local, supervise_remote):
        threading.Thread(target=observer, daemon=True).start()


@contextlib.contextmanager
def _client_slot(client):
    if client not in ("cli", "desktop", "web"):
        raise ValueError("未知的受管客户端")
    if client == "cli":
        yield
        return
    fd = os.open(_registry() / (client + ".lock"), os.O_NOFOLLOW | os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StartupFailure("SLOT_BUSY") from None
        yield
    finally:
        os.close(fd)


def _command(client, arguments, port):
    if client == "cli":
        if any(arg == "--desktop" or arg.startswith("--desktop=") for arg in arguments):
            raise ValueError("受管 CLI 不允许通过 --desktop 把会话交给另一个应用")
        program = shutil.which("claude")
        if not program:
            raise ValueError("未在 PATH 中找到 Claude Code CLI")
        return [program, *arguments]
    if arguments:
        raise ValueError("桌面版与网页受管模式不接受额外启动参数")
    if client == "web":
        from .chrome_web import web_command
        return web_command(port)
    if any(row[3] == _DESKTOP for row in _processes()):
        raise StartupFailure("CLIENT_OPEN")
    if not os.access(_DESKTOP, os.X_OK):
        raise ValueError("未找到可执行的 Claude 桌面版")
    return [_DESKTOP]


def _native_instance(pid, expected_start=None):
    return next((p for p in _processes() if p[0] == pid and p[1] == os.getuid()
                 and p[3] == _DESKTOP and (not expected_start or p[2] == expected_start)), None)


def _verify_desktop_proxy():
    script = '''ObjC.import("Foundation");
      const d=$.NSUserDefaults.alloc.initWithSuiteName("com.anthropic.claudefordesktop");
      const key=$("egressProxyUrl"), pac=$("egressProxyPacUrl");
      const value=ObjC.unwrap(d.stringForKey(key)), config=ObjC.unwrap(d.stringForKey(pac));
      String(Boolean(d.objectIsForcedForKey(key)) && !config && value==="http://127.0.0.1:47836");'''
    if _output(["/usr/bin/osascript", "-l", "JavaScript", "-e", script]).strip() != "true":
        raise ValueError("原生 Claude 需要受管的固定代理 127.0.0.1:47836，并关闭 PAC。")


@contextlib.contextmanager
def _startup_check(code):
    try:
        yield
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise StartupFailure(code, str(exc)) from None


def _supervise(arguments, client, expected, latch, attach_pid=None):
    with _startup_check("PROXY"):
        base = _identity()
    existing = None
    if client == "desktop":
        from .native_firewall import assert_desktop_firewall
        with _startup_check("DESKTOP_PROTECTION"):
            assert_desktop_firewall(DESKTOP_PORT)
            _verify_desktop_proxy()
        if attach_pid is not None:
            existing = _native_instance(attach_pid, os.environ.get("PREFLIGHT_DESKTOP_START"))
            if existing is None:
                raise ValueError("需要保护的原生 Claude 进程已退出或变化")
        relay = LockedRelay(base.port, listen_port=DESKTOP_PORT, start_paused=True)
    else:
        relay = LockedRelay(base.port)
    stop = threading.Event()
    child = None
    previous = {}
    ending = []
    def handler(number, _frame):
        if number == signal.SIGINT and child is not None:
            # The foreground terminal sends SIGINT to this entire job. The
            # client's own handler controls cancellation and interactive input.
            return
        ending.append(number)
    try:
        latch.attach(relay)
        if client == "web":
            from .chrome_web import verify_chrome_proxy
            with _startup_check("WEB_PROTECTION"):
                verify_chrome_proxy()
            prefix = []
            description = "专用 Chrome 窗口：普通网页请求使用已验证的固定代理。"
        elif client == "desktop":
            prefix = []
            description = "原生桌面模式：已核对 LuLu 定向规则，使用固定的本机中继。"
        else:
            policy = _sandbox_profile(relay.port)
            _verify_sandbox(policy, relay.port)
            prefix = [_SANDBOX, "-p", policy]
            description = "macOS 进程沙盒：直接网络连接仅允许本地受管中继。"
        check_port = base.port if client == "desktop" else relay.port
        with _startup_check("PROXY"):
            if _trace_ip(check_port) != expected or _identity() != base:
                raise ValueError("受管通道的 IP 或 OneVPN 状态与启动前的检测不一致")
        command = None if existing else _command(client, arguments, relay.port)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[number] = signal.signal(number, handler)
        if ending or latch.locked.is_set():
            raise ValueError("启动已取消或受管网络已锁定")
        relay.activate()
        started = time.monotonic()
        print(description, file=sys.stderr, flush=True)
        if existing:
            _watch(latch, stop, base, expected, relay.port)
            notify_dashboard()
            while not ending and _native_instance(existing[0], existing[2]):
                stop.wait(1)
            return 0
        child = subprocess.Popen([*prefix, *command], env=_environment(relay.port),
                                 close_fds=True)
        _watch(latch, stop, base, expected, relay.port)
        announced = False
        while child.poll() is None:
            if not announced and time.monotonic() - started >= 1.5:
                notify_dashboard()
                announced = True
            if ending:
                latch.lock("监护程序正在退出")
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                break
            time.sleep(.1)
        code = child.wait(timeout=3)
        if client != "cli" and code == 0 and time.monotonic() - started < 1.5:
            raise ValueError("客户端立即退出，未确认建立独立受管会话")
        if client == "desktop" and code:
            print("Claude 桌面版未正常退出，请检查本机代理描述文件与 LuLu 状态。",
                  file=sys.stderr)
        return code if code >= 0 else 128 - code
    finally:
        stop.set()
        if child is not None and child.poll() is None:
            relay.lock()
            child.kill()
            child.wait(timeout=3)
        relay.close()
        for number, old in previous.items():
            signal.signal(number, old)


def run_guard(arguments, expected_ip, client="cli", attach_pid=None):
    """Launch an isolated client. A lock is latched until the client exits."""
    try:
        if sys.platform != "darwin" or (client == "cli" and not os.access(_SANDBOX, os.X_OK)):
            raise ValueError("受管模式需要 macOS；终端模式另需系统提供 sandbox-exec")
        address = ipaddress.ip_address(expected_ip)
        if not address.is_global or address.is_multicast or "%" in str(address):
            raise ValueError("需要已验证的公网出口 IP")
        if any(stat.S_ISSOCK(os.fstat(fd).st_mode) for fd in (0, 1, 2)):
            raise ValueError("受管客户端拒绝继承套接字标准输入或输出")
        latch = _Latch()
        with _client_slot(client), _control(latch):
            return _supervise(arguments, client, str(address), latch, attach_pid)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if isinstance(exc, StartupFailure):
            notify_dashboard(exc.code)
        print(f"Preflight：受管启动失败（{exc}）。", file=sys.stderr)
        return 2
