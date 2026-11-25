import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import json
import unittest
import http.server

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netcheck


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class DnsTcpTests(unittest.TestCase):
    def test_dns_localhost(self):
        ok, msg, _ = netcheck.check_dns("localhost")
        self.assertTrue(ok, msg)

    def test_dns_invalid_name_fails(self):
        ok, _, _ = netcheck.check_dns("no-such-host.invalid")
        self.assertFalse(ok)

    def test_tcp_open_and_closed(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(netcheck.check_tcp("127.0.0.1", port)[0])
        finally:
            srv.close()
        self.assertFalse(netcheck.check_tcp("127.0.0.1", port, timeout=1)[0])


class TlsTests(unittest.TestCase):
    def _server(self, certfile, keyfile, port):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)

        def loop():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    ctx.wrap_socket(c, server_side=True).close()
                except (ssl.SSLError, OSError):
                    pass
        threading.Thread(target=loop, daemon=True).start()
        return srv

    def _cert(self, d, days):
        cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", str(days), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                       check=True, capture_output=True)
        return cert, key

    def test_valid_cert_ok_and_expiring_cert_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            cert, key = self._cert(d, 90)
            port = free_port()
            srv = self._server(cert, key, port)
            try:
                ok, msg, _ = netcheck.check_tls("localhost", port, cafile=cert)
                self.assertTrue(ok, msg)
                ok, msg, _ = netcheck.check_tls("localhost", port, warn_days=200, cafile=cert)
                self.assertFalse(ok)
                self.assertIn("expires in", msg)
            finally:
                srv.close()

    def test_untrusted_cert_fails(self):
        with tempfile.TemporaryDirectory() as d:
            cert, key = self._cert(d, 90)
            port = free_port()
            srv = self._server(cert, key, port)
            try:
                ok, msg, _ = netcheck.check_tls("localhost", port)
                self.assertFalse(ok)
            finally:
                srv.close()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = {"/ok": 200, "/gone": 404, "/moved": 301}.get(self.path, 500)
        self.send_response(code)
        if code == 301:
            self.send_header("Location", "/ok")
        self.end_headers()

    def log_message(self, *a):
        pass


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_status_match(self):
        self.assertTrue(netcheck.check_http(self.base + "/ok")[0])

    def test_status_mismatch_reports_codes(self):
        ok, msg, _ = netcheck.check_http(self.base + "/gone")
        self.assertFalse(ok)
        self.assertIn("404", msg)

    def test_expected_non_200_and_redirect_not_followed(self):
        self.assertTrue(netcheck.check_http(self.base + "/gone", expected=404)[0])
        self.assertTrue(netcheck.check_http(self.base + "/moved", expected=301)[0])

    def test_connection_refused_fails(self):
        port = free_port()
        self.assertFalse(netcheck.check_http(f"http://127.0.0.1:{port}/", timeout=1)[0])


class ParallelAndCliTests(unittest.TestCase):
    def test_parallel_keeps_input_order(self):
        lines = ["dns localhost", "dns no-such-host.invalid", "dns localhost"]
        res = netcheck.run(lines, workers=3)
        self.assertEqual([r[0] for r in res], lines)
        self.assertEqual([r[1] for r in res], [True, False, True])

    def test_json_output_and_exit_code(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("dns localhost\ndns no-such-host.invalid\n")
        path = f.name
        script = os.path.join(os.path.dirname(__file__), "..", "netcheck.py")
        p = subprocess.run([sys.executable, script, path, "--json"], capture_output=True, text=True)
        os.unlink(path)
        self.assertEqual(p.returncode, 1)
        data = json.loads(p.stdout)
        self.assertEqual([d["ok"] for d in data], [True, False])
        self.assertEqual(set(data[0]), {"check", "ok", "message", "ms"})


class RunTests(unittest.TestCase):
    def test_run_parses_and_reports(self):
        res = netcheck.run(["# comment", "", "dns localhost", "bogus line"])
        self.assertEqual(len(res), 2)
        self.assertTrue(res[0][1])
        self.assertFalse(res[1][1])


if __name__ == "__main__":
    unittest.main()
