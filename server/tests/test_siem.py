import socket

from fastapi.testclient import TestClient

from axfilter.app import Config, create_app
from axfilter.siem import SiemForwarder, to_cef, to_json, to_syslog

KEYS = {"agent": "a", "viewer": "v", "admin": "d"}


def test_format_functions():
    ev = {"event": "prompt.block", "action": "block", "name": "blk",
          "fields": {"service": "ChatGPT", "types": "RRN", "pipe": "a|b", "eq": "x=y"}}
    cef = to_cef(ev)
    assert cef.startswith("CEF:0|AXFilter|AXFilter|1.0|prompt.block|blk|8|")
    assert "pipe=a|b" in cef and "eq=x\\=y" in cef   # extension value escaping
    assert to_syslog(ev).startswith("<") and "prompt.block" in to_syslog(ev)
    assert '"service": "ChatGPT"' in to_json(ev)


def test_file_sink_writes_metadata_only(tmp_path):
    out = tmp_path / "siem.log"
    fwd = SiemForwarder(sink="file", fmt="cef", target=str(out))
    fwd.emit("prompt.block", action="block", service="ChatGPT", user="kim",
             src="10.0.0.1", types="RRN", rid="r1")
    line = out.read_text().strip()
    assert "CEF:0|AXFilter" in line and "types=RRN" in line


def test_udp_sink_receives(tmp_path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2)
    port = sock.getsockname()[1]
    SiemForwarder(sink="udp", fmt="syslog", target=f"127.0.0.1:{port}").emit(
        "prompt.mask", action="mask", service="Claude", types="EMAIL")
    data, _ = sock.recvfrom(4096)
    sock.close()
    assert b"prompt.mask" in data


def test_emit_never_raises_on_bad_target():
    SiemForwarder(sink="file", fmt="cef", target="/no/such/dir/x.log").emit("x")  # no exception
    SiemForwarder(sink="none").emit("x")


def test_inspect_forwards_to_siem_without_prompt_text(tmp_path):
    out = tmp_path / "s.log"
    cfg = Config(str(tmp_path / "d.db"), b"\x41" * 32, KEYS,
                 siem=SiemForwarder(sink="file", fmt="cef", target=str(out)))
    c = TestClient(create_app(cfg))
    c.post("/v1/inspect", headers={"X-API-Key": "a"},
           json={"service": "ChatGPT", "user": "kim", "ip": "10.0.0.1", "text": "메일 secret@corp.com"})
    log = out.read_text()
    assert "prompt.mask" in log and "types=EMAIL" in log
    assert "secret@corp.com" not in log and "메일" not in log   # no prompt text / values
