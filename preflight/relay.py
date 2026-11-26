"""A loopback CONNECT relay with a one-way network lock for guarded sessions."""

import errno
import re
import select
import socket
import threading
import time


_HEADER_LIMIT = 16384
_HANDSHAKE_SECONDS = 5
_BUFFER_LIMIT = 65536
_HOST_ROOTS = ("anthropic.com", "claude.ai", "claude.com", "claude.app",
               "claudeusercontent.com", "claudemcpcontent.com")
_SIGN_IN_HOSTS = frozenset(("challenges.cloudflare.com", "accounts.google.com",
                            "www.gstatic.com", "ssl.gstatic.com"))
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*")
_CONNECTING = {0, errno.EISCONN, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY}


class _InvalidHeader(ValueError):
    pass


def _receive_header(sock, deadline):
    data = bytearray()
    while True:
        end = data.find(b"\r\n\r\n")
        if end >= 0:
            if end + 4 > _HEADER_LIMIT:
                raise _InvalidHeader()
            return bytes(data[:end]), bytes(data[end + 4:])
        if len(data) >= _HEADER_LIMIT:
            raise _InvalidHeader()
        _wait(sock, False, deadline)
        try:
            part = sock.recv(8192)
        except BlockingIOError:
            continue
        if not part:
            raise ConnectionError("peer closed")
        data.extend(part)


def _authority(header):
    lines = header.split(b"\r\n")
    request = re.fullmatch(rb"CONNECT ([A-Za-z0-9.-]+):443 HTTP/1\.([01])", lines[0])
    if not request:
        raise _InvalidHeader()
    host = request[1].decode("ascii").lower()
    allowed = host in _SIGN_IN_HOSTS or any(
        host == root or host.endswith("." + root) for root in _HOST_ROOTS)
    if (len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split("."))
            or not allowed):
        raise _InvalidHeader()
    host_header = None
    for line in lines[1:]:
        if not _HEADER.fullmatch(line):
            raise _InvalidHeader()
        name, value = line.split(b":", 1)
        name, value = name.lower(), value.strip()
        if name == b"host":
            if host_header is not None or value.lower() not in (request[1].lower(), request[1].lower() + b":443"):
                raise _InvalidHeader()
            host_header = value
        if name == b"transfer-encoding" or (name == b"content-length" and value != b"0"):
            raise _InvalidHeader()
    if request[2] == b"1" and host_header is None:
        raise _InvalidHeader()
    return host + ":443"


def _wait(sock, writing, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    ready, writable, _ = select.select([] if writing else [sock], [sock] if writing else [], [], remaining)
    if not ready and not writable:
        raise TimeoutError()


def _dispose(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


class LockedRelay:
    """Only the fixed upstream can receive allowed tunnels. lock() is irreversible."""

    def __init__(self, upstream_port, listen_port=0, start_paused=False):
        if type(upstream_port) is not int or not 1 <= upstream_port <= 65535:
            raise ValueError("OneVPN 代理端口无效")
        self._upstream_port = upstream_port
        self._guard = threading.Lock()
        self._locked = False
        self._armed = not start_paused
        self._closed = False
        self._sockets = set()
        self._workers = set()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(("127.0.0.1", listen_port))
            self._port = self._listener.getsockname()[1]
            if self._port == upstream_port:
                raise OSError("本机中继端口与代理端口冲突")
            self._listener.listen(32)
            self._listener.settimeout(0.2)
            self._thread = threading.Thread(target=self._accept, name="preflight-listener", daemon=True)
            self._thread.start()
        except BaseException:
            self._listener.close()
            raise

    @property
    def port(self):
        return self._port

    def activate(self):
        with self._guard:
            if self._locked or self._closed:
                raise ValueError("本会话已锁定")
            self._armed = True

    def lock(self):
        # All nonblocking socket writes and upstream connects hold this same
        # mutex. A packet already passed to the OS cannot be recalled.
        with self._guard:
            self._locked = True
            for sock in self._sockets:
                _dispose(sock)
            self._sockets.clear()
        # Keep the port reserved until close(), including while a locked child
        # is winding down. New clients are immediately disconnected.

    def close(self):
        self.lock()
        with self._guard:
            if not self._closed:
                self._closed = True
                _dispose(self._listener)
            workers = tuple(self._workers)
        self._thread.join()
        for worker in workers:
            worker.join()

    def _accept(self):
        while True:
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._guard:
                if self._locked or not self._armed or len(self._workers) >= 64:
                    _dispose(client)
                    continue
                client.setblocking(False)
                self._sockets.add(client)
                worker = threading.Thread(target=self._run, args=(client,), name="preflight-tunnel", daemon=True)
                self._workers.add(worker)
                try:
                    worker.start()
                except RuntimeError:
                    self._workers.discard(worker)
                    self._sockets.discard(client)
                    _dispose(client)

    def _write(self, sock, data):
        with self._guard:
            if self._locked:
                raise ConnectionError("locked")
            try:
                sent = sock.send(data)
            except BlockingIOError:
                return 0
            if not sent:
                raise ConnectionError("peer closed")
            return sent

    def _send_all(self, sock, data, deadline):
        while data:
            _wait(sock, True, deadline)
            data = data[self._write(sock, data):]

    def _connect(self, upstream, deadline):
        with self._guard:
            if self._locked:
                raise ConnectionError("locked")
            upstream.setblocking(False)
            self._sockets.add(upstream)
            code = upstream.connect_ex(("127.0.0.1", self._upstream_port))
        if code not in _CONNECTING:
            raise ConnectionError("upstream unavailable")
        _wait(upstream, True, deadline)
        if upstream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
            raise ConnectionError("upstream unavailable")

    def _run(self, client):
        upstream = None
        deadline = time.monotonic() + _HANDSHAKE_SECONDS
        try:
            try:
                header, client_data = _receive_header(client, deadline)
                authority = _authority(header)
            except _InvalidHeader:
                self._send_all(client, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", deadline)
                return
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self._connect(upstream, deadline)
                request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii")
                self._send_all(upstream, request, deadline)
                reply, upstream_data = _receive_header(upstream, deadline)
                status = reply.split(b"\r\n", 1)[0]
                if not re.fullmatch(rb"HTTP/1\.[01] 2[0-9]{2}(?: [\x20-\x7e]*)?", status):
                    raise _InvalidHeader()
            except (OSError, _InvalidHeader):
                self._send_all(client, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", deadline)
                return
            self._send_all(client, b"HTTP/1.1 200 Connection Established\r\n\r\n", deadline)
            self._tunnel(client, upstream, client_data, upstream_data)
        except (OSError, ValueError):
            # Locking closes descriptors underneath pending select/recv calls.
            pass
        finally:
            with self._guard:
                for sock in (client, upstream):
                    if sock is not None:
                        self._sockets.discard(sock)
                        _dispose(sock)
                self._workers.discard(threading.current_thread())

    def _tunnel(self, client, upstream, client_data, upstream_data):
        peer = {client: upstream, upstream: client}
        pending = {upstream: bytearray(client_data), client: bytearray(upstream_data)}
        reading = set(peer)
        shutting = set()
        while reading or any(pending.values()):
            readers = [s for s in reading if len(pending[peer[s]]) < _BUFFER_LIMIT]
            writers = [s for s in peer if pending[s]]
            ready, writable, _ = select.select(readers, writers, [], 0.5)
            for sock in writable:
                sent = self._write(sock, pending[sock])
                del pending[sock][:sent]
            for sock in ready:
                outbound = pending[peer[sock]]
                try:
                    chunk = sock.recv(min(16384, _BUFFER_LIMIT - len(outbound)))
                except BlockingIOError:
                    continue
                if chunk:
                    outbound.extend(chunk)
                else:
                    reading.remove(sock)
                    shutting.add(peer[sock])
            # Flush buffered bytes before a directional EOF reaches its peer.
            for sock in tuple(shutting):
                if not pending[sock]:
                    sock.shutdown(socket.SHUT_WR)
                    shutting.remove(sock)
