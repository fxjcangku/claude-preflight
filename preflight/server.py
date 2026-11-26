"""Serve the dashboard, local measurement history and settings on loopback."""

import json
import re
import socket
import threading
import time
import webbrowser
from collections import deque
from concurrent.futures import Future
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import evaluate, load_target, save_target, snapshot, validate_target
from .desktop_launch import LocalLaunches


_STATIC = Path(__file__).resolve().parent / "static"
_DOCS = _STATIC.parent.parent / "docs"
_FILES = {
    "/": (_STATIC / "index.html", "text/html; charset=utf-8"),
    "/app.js": (_STATIC / "app.js", "application/javascript; charset=utf-8"),
    "/native-setup.js": (_STATIC / "native-setup.js", "application/javascript; charset=utf-8"),
    "/globe.js": (_STATIC / "globe.js", "application/javascript; charset=utf-8"),
    "/styles.css": (_STATIC / "styles.css", "text/css; charset=utf-8"),
    "/world.json": (_STATIC / "world.json", "application/json; charset=utf-8"),
    "/about/": (_DOCS / "index.html", "text/html; charset=utf-8"),
    "/about/index.html": (_DOCS / "index.html", "text/html; charset=utf-8"),
    "/about/intro.js": (_DOCS / "intro.js", "application/javascript; charset=utf-8"),
    "/about/intro.css": (_DOCS / "intro.css", "text/css; charset=utf-8"),
    "/about/logo.svg": (_DOCS / "logo.svg", "image/svg+xml"),
    "/favicon.ico": (_DOCS / "logo.svg", "image/svg+xml"),
    "/about/preview.png": (_DOCS / "preview.png", "image/png"),
}
_BODY_LIMIT = 4096
_READ_TIMEOUT = 4


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.target = load_target()
        self.lifecycle_lock = threading.Lock()
        self.launches = LocalLaunches()
        self.history = deque(maxlen=60)
        self.pending = None

    def read(self):
        with self.lock:
            history = list(self.history)
            target = self.target
        return {
            "target": target,
            "history": history,
            "launches": self.launches.status(),
            "assessment": evaluate(history[-1], target) if history else None,
        }

    def check(self):
        with self.lock:
            future = self.pending
            if future is None:
                self.pending = Future()
        if future is not None:
            future.result()
            return self.read()

        try:
            reading = snapshot()
        except Exception as exc:
            with self.lock:
                self.pending.set_exception(exc)
                self.pending = None
            raise
        with self.lock:
            self.history.append(reading)
            self.pending.set_result(None)
            self.pending = None
        return self.read()

    def update(self, data):
        if set(data) != {"country", "timezone"}:
            raise ValueError("设置必须包含目标地区和目标时区")
        target = validate_target(data["country"], data["timezone"])
        with self.lock:
            save_target(target)
            self.target = target
        return self.read()


class _RequestError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class _Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(_READ_TIMEOUT)

    def log_message(self, format, *args):
        # Request paths and probe results do not belong in terminal logs.
        pass

    def _reply(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, data):
        self._reply(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8")

    def send_error(self, code, message=None, explain=None):
        self._json(code, {"error": "不支持的请求"})

    def _require_host(self):
        if self.headers.get_all("Host") != [self.server.authority]:
            raise _RequestError(403, "请求主机与本机服务不匹配")

    def _body(self):
        if self.headers.get_all("Origin") != [self.server.origin]:
            raise _RequestError(403, "仅接受本机页面发起的请求")
        if (len(self.headers.get_all("Content-Type", [])) != 1 or
                self.headers.get_content_type() != "application/json"):
            raise _RequestError(415, "请求内容必须为 JSON")
        if self.headers.get_all("Transfer-Encoding"):
            raise _RequestError(400, "不支持该请求传输格式")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            raise _RequestError(400, "请求缺少有效长度")
        if len(lengths[0]) > 5 or int(lengths[0]) > _BODY_LIMIT:
            raise _RequestError(413, "请求内容过大")
        length = int(lengths[0])
        deadline = time.monotonic() + _READ_TIMEOUT
        body = bytearray()
        while len(body) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _RequestError(408, "读取请求超时")
            self.connection.settimeout(remaining)
            part = self.rfile.read1(length - len(body))
            if not part:
                raise _RequestError(400, "请求内容不完整")
            body.extend(part)
        self.connection.settimeout(_READ_TIMEOUT)
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, RecursionError):
            raise _RequestError(400, "无法解析 JSON") from None
        if not isinstance(data, dict):
            raise _RequestError(400, "请求内容必须为 JSON 对象")
        return data

    def _dispatch(self):
        self._require_host()
        path = self.path.partition("?")[0]
        state = self.server.state
        if self.command == "GET":
            if path == "/api/state":
                self._json(200, state.read())
            elif path == "/api/readiness":
                from .status_check import collect_readiness
                self._json(200, collect_readiness())
            elif path in _FILES:
                source, mime = _FILES[path]
                try:
                    body = source.read_bytes()
                except FileNotFoundError:
                    raise _RequestError(404, "资源不存在") from None
                self._reply(200, body, mime)
            else:
                raise _RequestError(404, "资源不存在")
        else:
            if path not in ("/api/check", "/api/settings", "/api/lock", "/api/launch"):
                raise _RequestError(404, "资源不存在")
            data = self._body()
            if path == "/api/launch":
                if set(data) != {"client"} or data["client"] not in ("web", "desktop"):
                    raise _RequestError(400, "请选择专用网页或 Claude 桌面版")
                try:
                    with state.lifecycle_lock:
                        state.launches.launch(data["client"])
                except ValueError as exc:
                    raise _RequestError(409, str(exc)) from None
                self._json(202, state.read())
                return
            if path == "/api/lock":
                if data:
                    raise _RequestError(400, "锁网请求应为空对象")
                from .guard import lock_sessions
                with state.lifecycle_lock:
                    cancelled = state.launches.cancel_starting()
                    confirmed, uncertain = lock_sessions()
                self._json(200, {"confirmed": confirmed, "unconfirmed": uncertain, "cancelled": cancelled})
                return
            if path == "/api/check":
                if data:
                    raise _RequestError(400, "检测请求应为空对象")
                updated = state.check()
            else:
                try:
                    updated = state.update(data)
                except ValueError as exc:
                    raise _RequestError(400, str(exc)) from None
            self._json(200, updated)

    def _handle(self):
        try:
            self._dispatch()
        except _RequestError as exc:
            self._json(exc.status, {"error": str(exc)})
        except socket.timeout:
            self._json(408, {"error": "读取请求超时"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(500, {"error": "本机服务无法完成请求"})

    do_GET = _handle
    do_POST = _handle


class _LocalServer(ThreadingHTTPServer):
    def __init__(self, port):
        super().__init__(("127.0.0.1", port), _Handler)
        try:
            self.state = _State()
        except Exception:
            self.server_close()
            raise
        self.authority = "127.0.0.1"
        if self.server_port != 80:
            self.authority += f":{self.server_port}"
        self.origin = "http://" + self.authority


def serve(port=0, open_browser=True):
    with _LocalServer(port) as server:
        url = server.origin + "/"
        print(url, flush=True)
        if open_browser:
            threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return
