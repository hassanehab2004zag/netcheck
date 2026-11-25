"""Small network health checker: DNS, TCP port and TLS certificate expiry.

Usage:
    python3 netcheck.py targets.txt
targets.txt, one per line:
    dns example.com
    tcp 192.0.2.10 443
    tls example.com 443
    http http://example.com 200
Options: --json (machine-readable output), --workers N (parallel checks),
--warn-days N (TLS expiry warning threshold).
Exit code is 1 if any check fails. Uses only the standard library.
ICMP ping is not used because it needs raw sockets; TCP connect checks stand in for reachability.
"""
import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


def check_dns(host, timeout=3.0):
    start = time.monotonic()
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
        return True, f"resolved to {', '.join(addrs)}", time.monotonic() - start
    except socket.gaierror as e:
        return False, f"dns error: {e}", time.monotonic() - start


def check_tcp(host, port, timeout=3.0):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "port open", time.monotonic() - start
    except OSError as e:
        return False, f"connect failed: {e}", time.monotonic() - start


def check_tls(host, port, warn_days=14, timeout=5.0, cafile=None):
    start = time.monotonic()
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            return False, f"certificate expired {-days} days ago", time.monotonic() - start
        if days < warn_days:
            return False, f"certificate expires in {days} days", time.monotonic() - start
        return True, f"certificate valid, {days} days left", time.monotonic() - start
    except (OSError, ssl.SSLError) as e:
        return False, f"tls error: {e}", time.monotonic() - start


def check_http(url, expected=200, timeout=5.0):
    """GET url and compare the status code with `expected`. Redirects are not followed."""
    start = time.monotonic()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(url, timeout=timeout) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"http error: {e}", time.monotonic() - start
    if code == expected:
        return True, f"status {code}", time.monotonic() - start
    return False, f"status {code}, expected {expected}", time.monotonic() - start


def run_one(line, warn_days=14):
    parts = line.split()
    kind = parts[0]
    try:
        if kind == "dns" and len(parts) == 2:
            ok, msg, t = check_dns(parts[1])
        elif kind == "tcp" and len(parts) == 3:
            ok, msg, t = check_tcp(parts[1], int(parts[2]))
        elif kind == "tls" and len(parts) == 3:
            ok, msg, t = check_tls(parts[1], int(parts[2]), warn_days=warn_days)
        elif kind == "http" and len(parts) in (2, 3):
            ok, msg, t = check_http(parts[1], int(parts[2]) if len(parts) == 3 else 200)
        else:
            ok, msg, t = False, f"bad line: {line}", 0.0
    except ValueError:
        ok, msg, t = False, f"bad line: {line}", 0.0
    return (line, ok, msg, t)


def run(lines, workers=1, warn_days=14):
    """Run all checks; results keep the order of the input file."""
    todo = [l.strip() for l in lines]
    todo = [l for l in todo if l and not l.startswith("#")]
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(lambda l: run_one(l, warn_days), todo))


def main(argv):
    p = argparse.ArgumentParser(description="DNS, TCP, TLS and HTTP checks from a file.")
    p.add_argument("targets")
    p.add_argument("--json", action="store_true", help="print results as JSON")
    p.add_argument("--workers", type=int, default=4, help="parallel checks (default 4)")
    p.add_argument("--warn-days", type=int, default=14, help="TLS expiry warning days")
    try:
        args = p.parse_args(argv[1:])
    except SystemExit:
        return 2
    with open(args.targets) as f:
        results = run(f, workers=args.workers, warn_days=args.warn_days)
    if args.json:
        print(json.dumps([{"check": l, "ok": ok, "message": m, "ms": round(t * 1000)}
                          for l, ok, m, t in results], indent=2))
    else:
        for line, ok, msg, t in results:
            print(f'{"OK  " if ok else "FAIL"} {line:<30} {msg} ({t*1000:.0f} ms)')
    return 0 if all(r[1] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
