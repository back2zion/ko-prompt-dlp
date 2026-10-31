"""Forward security events to a SIEM in CEF, RFC5424 syslog, or JSON lines.

Only metadata is exported — never the prompt text or the detected values — so
hooking up a SIEM does not create a second copy of sensitive data.
Sinks: file (append) or UDP syslog. Failures never break a request.
"""
from __future__ import annotations

import json
import logging
import socket
import time
from dataclasses import dataclass

log = logging.getLogger("axfilter.siem")
_VENDOR, _PRODUCT, _VERSION = "AXFilter", "AXFilter", "1.0"

# CEF severity by action.
_SEV = {"block": 8, "mask": 5, "allow": 2}


def _cef_escape(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _ext_escape(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef(ev: dict) -> str:
    name = ev.get("name", ev.get("event", "event"))
    sev = _SEV.get(ev.get("action", ""), 4)
    ext = " ".join(f"{k}={_ext_escape(v)}" for k, v in ev.get("fields", {}).items() if v not in (None, ""))
    sig = _cef_escape(ev.get("event", "event"))
    return f"CEF:0|{_VENDOR}|{_PRODUCT}|{_VERSION}|{sig}|{_cef_escape(name)}|{sev}|{ext}"


def to_syslog(ev: dict, host: str = "axfilter") -> str:
    # RFC5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ev.get("ts", time.time())))
    pri = 8 * 1 + (3 if ev.get("action") == "block" else 6)  # facility user(1)
    msg = json.dumps(ev.get("fields", {}), ensure_ascii=False)
    return f"<{pri}>1 {ts} {host} axfilter - {ev.get('event','event')} - {msg}"


def to_json(ev: dict) -> str:
    return json.dumps({"event": ev.get("event"), "ts": ev.get("ts", int(time.time())),
                       **ev.get("fields", {})}, ensure_ascii=False)


_FORMATTERS = {"cef": to_cef, "syslog": to_syslog, "json": to_json}


@dataclass
class SiemForwarder:
    sink: str = "none"          # none | file | udp
    fmt: str = "cef"            # cef | syslog | json
    target: str = ""            # file path, or host:port for udp

    def emit(self, event: str, *, ts: int | None = None, action: str | None = None,
             name: str | None = None, **fields) -> None:
        if self.sink == "none":
            return
        ev = {"event": event, "ts": ts or int(time.time()), "action": action,
              "name": name or event, "fields": fields}
        try:
            line = _FORMATTERS[self.fmt](ev)
            if self.sink == "file":
                with open(self.target, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            elif self.sink == "udp":
                host, _, port = self.target.partition(":")
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.sendto(line.encode("utf-8"), (host, int(port)))
                finally:
                    s.close()
        except Exception as e:                 # SIEM must never break the request path
            log.warning("siem emit failed: %s", e)
