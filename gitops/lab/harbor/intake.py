"""The Harbor's management intake (federation design, stage 4): what a federation partner sends on the
management class, kept for the ring-side evaluator. Only three kinds, JSON objects only, small; each record carries the
partner identity Envoy took from the verified client certificate (x-forwarded-client-cert, set by the Harbor and
never accepted from the client), and the time it arrived.

  POST /mgmt/state     the partner's ladder events (an incident, a finding, its resolution)
  POST /mgmt/logs      log excerpts the agreement names
  POST /mgmt/evidence  evidence items (FTEF 0.1 shape) that re-evaluate the partner
  GET  /mgmt/<kind>    the last records of that kind this partner sent (its receipt; the evaluator reads the files)

A partner sees only its own records and its writes are bounded: a rate per partner and a
quota of stored bytes per partner and kind. A refusal says why and what completes the intent.
"""
import json
import os
import re
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE = os.environ.get("INTAKE_DIR", "/data")
KINDS = ("state", "logs", "evidence")
MAX = 65536
RATE = int(os.environ.get("INTAKE_RATE_PER_MIN", "30"))          # POSTs per partner per minute
QUOTA = int(os.environ.get("INTAKE_QUOTA_BYTES", str(1 << 20)))  # stored bytes per partner and kind
SHOWN = 50
NO_ID = {"error": "no verified partner identity", "next": "reach the intake through the Harbor with an admitted client certificate"}

LOCK = threading.Lock()
USED = defaultdict(int)          # (partner, kind) -> stored bytes
RECENT = defaultdict(deque)      # partner -> monotonic times of its accepted POSTs in the last minute


def partner(headers):
    m = re.search(r'URI=([^;,"]+)', headers.get("x-forwarded-client-cert", ""))
    return m.group(1) if m else None


def load() -> None:
    """Count what each partner already stored, so a restart does not reset the quota."""
    USED.clear()
    RECENT.clear()
    for kind in KINDS:
        path = os.path.join(STORE, f"{kind}.jsonl")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    p = json.loads(line).get("partner")
                except ValueError:
                    continue
                USED[(p, kind)] += len(line.encode())


class Intake(BaseHTTPRequestHandler):
    def _kind(self):
        m = re.fullmatch(r"/mgmt/(state|logs|evidence)/?", self.path.split("?")[0])
        return KINDS[KINDS.index(m.group(1))] if m else None   # the constant, so the file name never comes from the request

    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        kind, who = self._kind(), partner(self.headers)
        if not who:
            return self._send(403, NO_ID)
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            n = -1
        if not kind or n <= 0 or n > MAX:
            return self._send(400, {"error": "POST /mgmt/state|logs|evidence with a JSON object under 64 KiB"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self._send(400, {"error": "not JSON"})
        if not isinstance(body, dict):
            return self._send(400, {"error": "the body must be a JSON object"})
        rec = {"received": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "partner": who, "kind": kind, "body": body}
        line = json.dumps(rec) + "\n"
        size = len(line.encode())
        with LOCK:
            t, seen = time.monotonic(), RECENT[who]
            while seen and t - seen[0] > 60:
                seen.popleft()
            if len(seen) >= RATE:
                return self._send(429, {"error": f"more than {RATE} reports a minute from this partner",
                                        "next": "send again after a minute; the evaluator reads every minute, so one report a minute per kind is enough"})
            if USED[(who, kind)] + size > QUOTA:
                return self._send(507, {"error": f"this partner's {kind} records reached the intake's quota ({QUOTA} bytes)",
                                        "next": "ask the serving ring's operator: the evaluator has read what was sent; the quota is raised or the store rotated there"})
            with open(os.path.join(STORE, f"{kind}.jsonl"), "a", encoding="utf-8") as f:
                f.write(line)
            seen.append(t)
            USED[(who, kind)] += size
        self._send(202, {"accepted": kind, "received": rec["received"]})

    def do_GET(self):
        kind, who = self._kind(), partner(self.headers)
        if not who:
            return self._send(403, NO_ID)
        if not kind:
            return self._send(404, {"error": "unknown"})
        path = os.path.join(STORE, f"{kind}.jsonl")
        mine = []
        with LOCK:
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        if r.get("partner") == who:
                            mine.append(r)
        self._send(200, {"kind": kind, "partner": who, "records": mine[-SHOWN:]})

    def log_message(self, fmt, *args):
        print(json.dumps({"intake": self.command, "path": self.path.split("?")[0], "status": args[1] if len(args) > 1 else ""}), flush=True)


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6   # the ring is IPv6-only


if __name__ == "__main__":
    load()
    Server(("::", 8080), Intake).serve_forever()
