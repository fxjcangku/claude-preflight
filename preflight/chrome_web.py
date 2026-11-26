"""Guard ordinary web traffic in a separate Chrome instance using a fixed proxy."""

import http.server
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import threading


_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


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


def web_command(relay_port):
    """Use a persistent, owner-only profile; caller holds the web session lock."""
    support = Path.home() / "Library" / "Application Support"
    parent = _private_dir(support / "Claude Preflight")
    profile = _private_dir(parent / "Guarded Chrome")
    if os.path.lexists(profile / "SingletonLock"):
        raise ValueError("专用 Chrome 资料夹已有实例锁，请先完全退出相关浏览器")
    return _options(relay_port, profile) + ["--app=https://claude.ai/"]


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
