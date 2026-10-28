import base64
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import assetcheck as ac


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        want = "Basic " + base64.b64encode(b"admin:admin").decode()
        if self.headers.get("Authorization") == want:
            self.send_response(200)
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def web():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_detects_default_credentials(web):
    f = ac.check_host("127.0.0.1", ports={}, web_ports=(web,), delay=0)
    assert [x["severity"] for x in f] == ["critical"] and "admin/admin" in f[0]["issue"]


def test_strong_password_not_flagged(web):
    f = ac.check_host("127.0.0.1", ports={}, web_ports=(web,), delay=0,
                      creds_list=[("admin", "wrong")])
    assert f == []


def test_reports_open_risky_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]
    f = ac.check_host("127.0.0.1", ports={port: ("Redis", "high")}, web_ports=(), delay=0)
    s.close()
    assert f[0]["port"] == port and f[0]["severity"] == "high"


def test_scope_guards():
    assert ac.expand_scope(["# c", "10.0.0.0/30", "10.0.0.1"]) == ["10.0.0.1", "10.0.0.2"]
    with pytest.raises(ValueError):
        ac.expand_scope(["10.0.0.0/16"])
    with pytest.raises(ValueError):
        ac.expand_scope(["8.8.8.8"])
    assert ac.expand_scope(["8.8.8.8"], allow_public=True) == ["8.8.8.8"]


def test_requires_confirmation(tmp_path, capsys):
    p = tmp_path / "s.txt"
    p.write_text("127.0.0.1\n")
    assert ac.main(["--scope", str(p)]) == 2
