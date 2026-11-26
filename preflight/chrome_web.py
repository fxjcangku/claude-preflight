"""Guard ordinary web traffic in a separate Chrome instance using a fixed proxy."""

import http.server
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import threading


_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
_LANGUAGE_KEYS = ("accept_languages", "selected_languages")
# Chrome's ordinary content-language choices use language, script, region and variant subtags.
_LANGUAGE_TAG = re.compile(
    r"[A-Za-z]{2,3}(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?"
    r"(?:-(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*"
)


def _options(relay_port, profile):
    if type(relay_port) is not int or not 1 <= relay_port <= 65535:
        raise ValueError("本机中继端口无效")
    if not os.access(_CHROME, os.X_OK):
        raise ValueError("未找到已安装的 Google Chrome")
    return [
        _CHROME,
        f"--user-data-dir={profile}",
        f"--proxy-server=http://127.0.0.1:{relay_port}",
        "--proxy-bypass-list=<-loopback>",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic",
        "--disable-extensions",
        "--disable-background-mode",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-sync",
        "--disable-breakpad",
        "--disable-default-apps",
        "--no-first-run",
        "--no-default-browser-check",
        # The HTTP proxy resolves CONNECT hostnames. Chromium has no need for
        # local resolutions of named destinations in this dedicated instance.
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    ]


def _private_dir(path):
    path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid():
            raise ValueError("专用 Chrome 资料目录的所有者不正确")
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return path


def _unlocked(profile):
    if os.path.lexists(profile / "SingletonLock"):
        raise ValueError("专用 Chrome 资料夹已有实例锁，请先完全退出相关浏览器")


def _pref_string(path, key):
    """Only return the requested string from the regular browser's settings."""
    if path.is_symlink() or not path.is_file():
        return None
    try:
        result = subprocess.run(
            ["/usr/bin/plutil", "-extract", key, "raw", "-expect", "string",
             "-o", "-", "--", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3,
        )
        if not result.returncode:
            return result.stdout.decode("utf-8").removesuffix("\n")
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        pass
    return None


def _profile_name(root):
    name = _pref_string(root / "Local State", "profile.last_used")
    if name is None:
        return "Default"
    if re.fullmatch(r"Default|Profile [0-9]{1,8}", name):
        return name
    return None


def _language_list(value):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    tags = [tag.strip(" ") for tag in value.split(",")]
    if len(tags) <= 32 and all(_LANGUAGE_TAG.fullmatch(tag) for tag in tags):
        return ",".join(tags)
    return None


def _inherit_languages(source, target, target_name):
    source_name = _profile_name(source)
    if not source_name or (source / source_name).is_symlink():
        return
    prefs = source / source_name / "Preferences"
    desired = {key: _language_list(_pref_string(prefs, "intl." + key)) for key in _LANGUAGE_KEYS}
    languages = desired["accept_languages"] or desired["selected_languages"]
    if not languages:
        return
    desired = {key: value or languages for key, value in desired.items()}
    folder = _private_dir(target / target_name)
    path = folder / "Preferences"
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("专用 Chrome 偏好文件无效")
    try:
        with path.open(encoding="utf-8") as stream:
            existing = json.load(stream)
    except FileNotFoundError:
        existing = {}
    if not isinstance(existing, dict) or not isinstance(existing.get("intl", {}), dict):
        raise ValueError("无法读取专用 Chrome 的语言偏好")
    intl = existing.setdefault("intl", {})
    for key, value in desired.items():
        current = intl.get(key)
        if current not in (None, "") and _language_list(current) not in ("zh-CN,zh", value):
            return  # Honor language choices made in the dedicated profile itself.
    if all(intl.get(key) == value for key, value in desired.items()):
        return
    intl.update(desired)
    with tempfile.NamedTemporaryFile(dir=folder, delete=False) as staged:
        tmp = Path(staged.name)
        try:
            staged.write(json.dumps(existing, ensure_ascii=True, separators=(",", ":")).encode())
            staged.flush()
            os.fsync(staged.fileno())
            _unlocked(target)
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


def web_command(relay_port):
    """Use a persistent, owner-only profile; caller holds the web session lock."""
    support = Path.home() / "Library" / "Application Support"
    parent = _private_dir(support / "Claude Preflight")
    profile = _private_dir(parent / "Guarded Chrome")
    _unlocked(profile)
    command = _options(relay_port, profile)
    name = _profile_name(profile)
    if name:
        _inherit_languages(support / "Google" / "Chrome", profile, name)
        command.append(f"--profile-directory={name}")
    return command + ["--app=https://claude.ai/"]


class _Endpoint(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        # The local test server never opens a connection to any destination.
        self.send_error(403)


class _Origin(_Endpoint):
    def setup(self):
        super().setup()
        self.server.direct_hit.set()

    def do_GET(self):
        self.send_error(404)


class _TestProxy(_Endpoint):
    def do_GET(self):
        if self.path != self.server.probe_url:
            self.send_error(404)
            return
        # Drop the proxy listener before returning the page on the already
        # accepted socket. The image fetch therefore happens in the same
        # running Chrome instance, after its functioning proxy has vanished.
        self.server.server_close()
        self.server.page_served.set()
        page = (b'<!doctype html><p id="verdict">waiting</p>'
                b'<img src="/after-loss.png" '
                b'onerror="document.getElementById(\'verdict\').textContent=\'blocked\'" '
                b'onload="document.getElementById(\'verdict\').textContent=\'loaded\'">')
        self.send_response(200)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/html")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


def _serve_until(server, finished):
    server.timeout = 0.2
    while not finished.is_set():
        server.handle_request()


def verify_chrome_proxy():
    """Require a real Chrome page fetch through a local proxy, then a closed failure."""
    with tempfile.TemporaryDirectory(prefix="preflight-web-") as temp, \
            http.server.HTTPServer(("127.0.0.1", 0), _Origin) as origin, \
            http.server.HTTPServer(("127.0.0.1", 0), _TestProxy) as proxy:
        stop_origin = threading.Event()
        origin.direct_hit = threading.Event()
        proxy.page_served = threading.Event()
        proxy.probe_url = f"http://127.0.0.1:{origin.server_port}/before-loss"
        command = _options(proxy.server_port, Path(temp) / "profile") + [
            "--headless=new", "--disable-gpu", "--dump-dom",
            "--use-mock-keychain", "--password-store=basic", proxy.probe_url,
        ]
        threads = [
            threading.Thread(target=_serve_until, args=(origin, stop_origin), daemon=True),
            threading.Thread(target=_serve_until, args=(proxy, proxy.page_served), daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            proc = subprocess.Popen(
                command, env={"HOME": temp, "TMPDIR": temp, "PATH": os.defpath, "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True,
            )
            try:
                dom, _ = proc.communicate(timeout=20)
            except BaseException:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.communicate()
                raise
            if (proc.returncode or not proxy.page_served.is_set() or origin.direct_hit.is_set()
                    or b'<p id="verdict">blocked</p>' not in dom):
                raise ValueError("Chrome 未通过专用代理断线验证，已取消启动")
        finally:
            stop_origin.set()
            proxy.page_served.set()
            for thread in threads:
                thread.join(timeout=2)
