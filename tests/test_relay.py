import socket
import threading
import unittest
from unittest.mock import patch

from preflight.relay import LockedRelay


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy.bind(("127.0.0.1", 0))
        self.proxy.listen()
        self.proxy.settimeout(2)
        self.addCleanup(self.proxy.close)
        self.relay = LockedRelay(self.proxy.getsockname()[1])
        self.addCleanup(self.relay.close)

    def client(self):
        sock = socket.create_connection(("127.0.0.1", self.relay.port), timeout=2)
        self.addCleanup(sock.close)
        return sock

    def upstream(self):
        sock, address = self.proxy.accept()
        self.assertEqual(address[0], "127.0.0.1")
        sock.settimeout(2)
        self.addCleanup(sock.close)
        return sock

    def read_to(self, sock, end):
        data = bytearray()
        while end not in data:
            chunk = sock.recv(4096)
            self.assertTrue(chunk, "connection closed before expected bytes")
            data.extend(chunk)
        return bytes(data)

    def assert_closed(self, sock):
        try:
            self.assertEqual(sock.recv(1), b"")
        except ConnectionResetError:
            pass

    def test_rebuilds_connect_preserves_coalesced_bytes_and_half_close(self):
        client = self.client()
        client.sendall(b"CONNECT Api.Anthropic.Com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n"
                       b"Proxy-Authorization: Bearer private\r\nX-Extra: private\r\n\r\nFIRST")
        proxy = self.upstream()
        header = self.read_to(proxy, b"\r\n\r\n")
        self.assertEqual(header, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        proxy.sendall(b"HTTP/1.0 200 OK\r\nX-Secret: secret\r\n\r\nHELLO")
        self.assertEqual(self.read_to(client, b"HELLO"), b"HTTP/1.1 200 Connection Established\r\n\r\nHELLO")
        self.assertEqual(self.read_to(proxy, b"FIRST"), b"FIRST")
        client.sendall(b"second")
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(self.read_to(proxy, b"second"), b"second")
        self.assert_closed(proxy)
        proxy.sendall(b"final")
        proxy.shutdown(socket.SHUT_WR)
        self.assertEqual(self.read_to(client, b"final"), b"final")
        self.assert_closed(client)

    def test_login_verification_host_uses_the_same_upstream(self):
        authority = b"challenges.cloudflare.com:443"
        request = b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n"
        client = self.client()
        client.sendall(request)
        proxy = self.upstream()
        self.assertEqual(self.read_to(proxy, b"\r\n\r\n"), request)
        proxy.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertIn(b" 200 ", self.read_to(client, b"\r\n\r\n"))
        self.relay.lock()
        self.assert_closed(client)
        self.assert_closed(proxy)

    def test_mistyped_home_redirects_locally_only(self):
        for method in (b"GET", b"HEAD"):
            for uri in (b"http://https//claude.ai", b"http://https//claude.ai/"):
                with self.subTest(method=method, uri=uri):
                    client = self.client()
                    client.sendall(method + b" " + uri + b" HTTP/1.1\r\nHost: https\r\n\r\n")
                    response = self.read_to(client, b"\r\n\r\n")
                    self.assertTrue(response.startswith(b"HTTP/1.1 302 "))
                    self.assertIn(b"\r\nLocation: https://claude.ai/\r\n", response)
                    self.assert_closed(client)
        self.proxy.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.proxy.accept()

    def test_inactive_relay_never_redirects(self):
        for suspend in (self.relay.pause, self.relay.lock):
            suspend()
            client = self.client()
            try:
                client.sendall(b"GET http://https//claude.ai/ HTTP/1.1\r\nHost: https\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.assert_closed(client)
        self.proxy.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.proxy.accept()

    def test_google_sign_in_and_static_hosts_use_the_pinned_proxy(self):
        for host in ("accounts.google.com", "www.gstatic.com", "ssl.gstatic.com",
                     "js.hcaptcha.com", "newassets.hcaptcha.com", "api.hcaptcha.com"):
            with self.subTest(host=host):
                client = self.client()
                request = f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode()
                client.sendall(request)
                upstream = self.upstream()
                self.assertEqual(self.read_to(upstream, b"\r\n\r\n"), request)
                upstream.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                self.assertIn(b" 200 ", self.read_to(client, b"\r\n\r\n"))
                client.close()
                upstream.close()

    def test_reject_unapproved_targets_and_malformed_requests_before_upstream(self):
        requests = [
            b"GET / HTTP/1.0\r\n",
            b"GET http://https//claude.ai.fake/ HTTP/1.1\r\nHost: https\r\n",
            b"GET http://https//claude.ai/?next=other HTTP/1.1\r\nHost: https\r\n",
            b"GET http://user@https//claude.ai/ HTTP/1.1\r\nHost: https\r\n",
            b"GET http://https//claude.ai/other HTTP/1.1\r\nHost: https\r\n",
            b"POST http://https//claude.ai/ HTTP/1.1\r\nHost: https\r\n",
            b"GET http://https//claude.ai/ HTTP/1.0\r\n",
            b"GET http://https//claude.ai/ HTTP/1.1\r\nHost: other\r\n",
            b"GET http://https//claude.ai/ HTTP/1.1\r\nHost: https\r\nHost: https\r\n",
            b"GET http://https//claude.ai/ HTTP/1.1\r\nHost: https\r\nContent-Length: 1\r\n",
            b"CONNECT 127.0.0.1:443 HTTP/1.0\r\n",
            b"CONNECT api.anthropic.com.attacker.test:443 HTTP/1.0\r\n",
            b"CONNECT evilclaude.ai:443 HTTP/1.0\r\n",
            b"CONNECT cloudflare.com:443 HTTP/1.0\r\n",
            b"CONNECT other.challenges.cloudflare.com:443 HTTP/1.0\r\n",
            b"CONNECT challenges.cloudflare.com.example.test:443 HTTP/1.0\r\n",
            b"CONNECT accounts.google.com.example.test:443 HTTP/1.0\r\n",
            b"CONNECT drive.google.com:443 HTTP/1.0\r\n",
            b"CONNECT notwww.gstatic.com:443 HTTP/1.0\r\n",
            b"CONNECT evilhcaptcha.com:443 HTTP/1.0\r\n",
            b"CONNECT js.hcaptcha.com.attacker.test:443 HTTP/1.0\r\n",
            b"CONNECT bad..claude.ai:443 HTTP/1.0\r\n",
            b"CONNECT claude.ai:80 HTTP/1.0\r\n",
            b"CONNECT claude.ai@other:443 HTTP/1.0\r\n",
            b"CONNECT claude.ai:443 HTTP/1.1\r\nHost: other:443\r\n",
            b"CONNECT claude.ai:443 HTTP/1.0\r\nInjected\x00: bad\r\n",
            b"CONNECT claude.ai:443 HTTP/1.0\r\nTransfer-Encoding: chunked\r\n",
            b"CONNECT claude.ai:443 HTTP/1.0\r\nX-Long: " + b"x" * 16400 + b"\r\n",
        ]
        for request in requests:
            with self.subTest(request=request[:90]):
                client = self.client()
                client.sendall(request + b"\r\n")
                self.assertIn(b" 403 ", self.read_to(client, b"\r\n\r\n"))
                client.close()
        self.proxy.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.proxy.accept()

    def test_lock_closes_active_pending_and_future_tunnels(self):
        ready = self.client()
        ready.sendall(b"CONNECT claude.ai:443 HTTP/1.0\r\n\r\n")
        active = self.upstream()
        self.read_to(active, b"\r\n\r\n")
        active.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        self.read_to(ready, b"\r\n\r\n")
        waiting = self.client()
        waiting.sendall(b"CONNECT claude.com:443 HTTP/1.0\r\n\r\n")
        pending = self.upstream()
        self.read_to(pending, b"\r\n\r\n")
        incomplete = self.client()
        incomplete.sendall(b"CONNECT")
        self.relay.lock()
        self.relay.lock()
        for sock in (ready, active, waiting, pending, incomplete, self.client()):
            self.assert_closed(sock)
        self.proxy.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.proxy.accept()
        self.relay.close()
        self.relay.close()

    def test_pause_cuts_old_tunnels_rejects_new_ones_and_can_resume(self):
        request = b"CONNECT claude.ai:443 HTTP/1.0\r\n\r\n"
        client = self.client()
        client.sendall(request)
        old = self.upstream()
        self.read_to(old, b"\r\n\r\n")
        old.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        self.read_to(client, b"\r\n\r\n")
        self.relay.pause()
        for sock in (old, client, self.client()):
            self.assert_closed(sock)
        self.proxy.settimeout(.05)
        with self.assertRaises(socket.timeout):
            self.proxy.accept()
        self.relay.activate()
        fresh = self.client()
        fresh.sendall(request)
        self.assertIn(b"CONNECT claude.ai:443", self.read_to(self.upstream(), b"\r\n\r\n"))
        self.relay.lock()
        self.relay.pause()
        with self.assertRaises(ValueError):
            self.relay.activate()
        self.assert_closed(self.client())

    def test_worker_between_read_and_connect_cannot_survive_pause(self):
        entered, release, paused = threading.Event(), threading.Event(), threading.Event()
        connect = self.relay._connect
        def delayed(*args):
            entered.set()
            release.wait(2)
            return connect(*args)
        def pause():
            self.relay.pause()
            paused.set()
        with patch.object(self.relay, "_connect", side_effect=delayed):
            client = self.client()
            client.sendall(b"CONNECT claude.ai:443 HTTP/1.0\r\n\r\n")
            self.assertTrue(entered.wait(1))
            worker = threading.Thread(target=pause)
            worker.start()
            try:
                self.assert_closed(client)
                self.assertFalse(paused.is_set())
            finally:
                release.set()
                worker.join(timeout=2)
            self.assertTrue(paused.is_set())
            self.relay.activate()
        self.proxy.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.proxy.accept()

    def test_upstream_refusal_is_sanitized(self):
        client = self.client()
        client.sendall(b"CONNECT claude.ai:443 HTTP/1.0\r\n\r\nEARLY")
        proxy = self.upstream()
        self.read_to(proxy, b"\r\n\r\n")
        proxy.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nX-Internal: secret\r\n\r\nsensitive")
        self.assertEqual(self.read_to(client, b"\r\n\r\n"), b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        self.assert_closed(client)


if __name__ == "__main__":
    unittest.main()
