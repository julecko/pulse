#!/usr/bin/env python3
"""End-to-end check for the pulse-server HTTP API.

Exercises auth (good/bad login, token required, logout invalidation) and every
query endpoint (hosts, host detail, history, raw reports, live SSE). The body
returned by each endpoint is printed below its checks; pass --no-data to hide it
or --max-body 0 to print it in full.

Usage:
    scripts/api_smoke_test.py --url http://127.0.0.1:9100 --user alice --password 'secret'
    scripts/api_smoke_test.py --user alice        # prompts for the password (no echo)

Env fallbacks: PULSE_API_URL, PULSE_API_USER, PULSE_API_PASSWORD.
If --password is omitted and PULSE_API_PASSWORD is unset, you are prompted.
Only uses the Python standard library.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 10


class ApiError(Exception):
    pass


def request(method, url, token=None, body=None, timeout=TIMEOUT):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, _decode(raw)
    except urllib.error.HTTPError as e:
        return e.code, _decode(e.read())


def _decode(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode("utf-8", "replace").strip()


class Runner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, cond, detail=""):
        mark = "PASS" if cond else "FAIL"
        print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))
        if cond:
            self.passed += 1
        else:
            self.failed += 1
        return cond


SHOW_DATA = True
MAX_BODY = 2000


def show(label, data):
    """Pretty-print a response payload beneath its check (unless --no-data)."""
    if not SHOW_DATA:
        return
    if data is None:
        text = "(empty body)"
    elif isinstance(data, str):
        text = data
    else:
        text = json.dumps(data, indent=2, sort_keys=True)
    if MAX_BODY and len(text) > MAX_BODY:
        text = text[:MAX_BODY] + f"\n… (+{len(text) - MAX_BODY} chars truncated; use --max-body 0)"
    print(f"  ── {label} ──")
    for line in text.splitlines():
        print(f"     {line}")


def sse_first_events(url, token, want=1, timeout=8):
    """Open the SSE stream and return up to `want` decoded `data:` payloads."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(url, headers=headers)
    events = []
    deadline = time.time() + timeout
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return events
            for rawline in resp:
                line = rawline.decode("utf-8", "replace").strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    try:
                        events.append(json.loads(payload))
                    except json.JSONDecodeError:
                        events.append(payload)
                    if len(events) >= want:
                        break
                if time.time() > deadline:
                    break
    except (urllib.error.URLError, TimeoutError, OSError):
        pass
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("PULSE_API_URL", "http://127.0.0.1:9100"))
    ap.add_argument("--user", default=os.environ.get("PULSE_API_USER", "alice"))
    ap.add_argument("--password", default=os.environ.get("PULSE_API_PASSWORD"),
                    help="account password; if omitted, you are prompted (no echo)")
    ap.add_argument("--wait-live", type=int, default=8, help="seconds to wait for a live SSE event")
    ap.add_argument("--data", action=argparse.BooleanOptionalAction, default=True,
                    help="print the response body from each endpoint (default: on)")
    ap.add_argument("--max-body", type=int, default=2000,
                    help="truncate printed bodies to this many chars (0 = no limit)")
    args = ap.parse_args()

    global SHOW_DATA, MAX_BODY
    SHOW_DATA = args.data
    MAX_BODY = args.max_body

    if not args.password:
        try:
            args.password = getpass.getpass(f"Password for {args.user!r}: ")
        except (EOFError, KeyboardInterrupt):
            print("\nno password provided", file=sys.stderr)
            return 1
    if not args.password:
        print("no password provided", file=sys.stderr)
        return 1

    base = args.url.rstrip("/") + "/api/v1"
    r = Runner()

    print(f"pulse API smoke test → {base}")

    # 1. health, unauthenticated
    status, body = request("GET", f"{base}/healthz")
    r.check("GET /healthz is 200", status == 200, f"got {status}")
    show("GET /healthz", body)

    # 2. protected route rejects no token
    status, _ = request("GET", f"{base}/hosts")
    r.check("GET /hosts without token is 401", status == 401, f"got {status}")

    # 3. login with wrong password
    status, _ = request("POST", f"{base}/login",
                        body={"username": args.user, "password": "definitely-wrong-XYZ-1"})
    r.check("login with bad password is 401", status == 401, f"got {status}")

    # 4. login for real
    status, payload = request("POST", f"{base}/login",
                              body={"username": args.user, "password": args.password})
    ok = r.check("login with correct password is 200", status == 200, f"got {status}: {payload}")
    if not ok or not isinstance(payload, dict) or "token" not in payload:
        print("\ncannot continue without a token")
        return 1
    token = payload["token"]
    r.check("login response has expires_at_ms", isinstance(payload.get("expires_at_ms"), int))
    show("POST /login", {**payload, "token": payload["token"][:8] + "…"})

    # 5. authenticated hosts list
    status, hosts = request("GET", f"{base}/hosts", token=token)
    ok = r.check("GET /hosts with token is 200", status == 200, f"got {status}")
    r.check("/hosts returns a list", isinstance(hosts, list))
    show("GET /hosts", hosts)

    if hosts:
        h = hosts[0]
        mid = h["machine_id"]
        print(f"  (using host {mid} / {h.get('hostname')!r})")
        for field in ("hostname", "first_seen_ms", "last_seen_ms", "report_count", "online"):
            r.check(f"/hosts item has {field}", field in h)

        status, detail = request("GET", f"{base}/hosts/{mid}", token=token)
        r.check("GET /hosts/{id} is 200", status == 200, f"got {status}")
        r.check("/hosts/{id} has a full report",
                isinstance(detail, dict) and "report" in detail and "metrics" in detail["report"])
        show(f"GET /hosts/{mid}", detail)

        now = int(time.time() * 1000)
        frm = now - 3600_000
        status, hist = request("GET",
                               f"{base}/hosts/{mid}/history?from={frm}&to={now}", token=token)
        ok = r.check("GET /hosts/{id}/history is 200", status == 200, f"got {status}")
        r.check("history has buckets list",
                isinstance(hist, dict) and isinstance(hist.get("buckets"), list))
        r.check("history echoes a bucket_ms > 0",
                isinstance(hist, dict) and hist.get("bucket_ms", 0) > 0)
        show(f"GET /hosts/{mid}/history", hist)

        status, reps = request("GET",
                               f"{base}/hosts/{mid}/reports?from={frm}&to={now}&limit=5", token=token)
        r.check("GET /hosts/{id}/reports is 200", status == 200, f"got {status}")
        r.check("reports is a list of <= 5", isinstance(reps, list) and len(reps) <= 5)
        show(f"GET /hosts/{mid}/reports", reps)

        status, notfound = request("GET", f"{base}/hosts/does-not-exist", token=token)
        r.check("GET /hosts/<unknown> is 404", status == 404, f"got {status}")
        show("GET /hosts/does-not-exist", notfound)

        # 6. live SSE — expect the seeded snapshot immediately
        print(f"  opening live stream (up to {args.wait_live}s)…")
        events = sse_first_events(f"{base}/live", token, want=1, timeout=args.wait_live)
        r.check("live stream delivered an event", len(events) >= 1,
                "no data: lines received")
        if events:
            r.check("live event looks like a report",
                    isinstance(events[0], dict) and "metrics" in events[0])
            show("GET /live (first event)", events[0])

        # SSE via ?token= query param (what a browser EventSource would use)
        events_q = sse_first_events(f"{args.url.rstrip('/')}/api/v1/live?token={token}",
                                    None, want=1, timeout=args.wait_live)
        r.check("live stream works with ?token= param", len(events_q) >= 1)
    else:
        print("  (no hosts reported yet — start an agent to exercise host endpoints)")

    # 7. logout invalidates the token
    status, _ = request("POST", f"{base}/logout", token=token)
    r.check("POST /logout is 204", status == 204, f"got {status}")
    status, _ = request("GET", f"{base}/hosts", token=token)
    r.check("token rejected after logout", status == 401, f"got {status}")

    print(f"\n{r.passed} passed, {r.failed} failed")
    return 0 if r.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
