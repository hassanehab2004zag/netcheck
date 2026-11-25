"""Small network health checker: DNS, TCP port and TLS certificate expiry.

Usage:
    python3 netcheck.py targets.txt
targets.txt, one per line:
    dns example.com
    tcp 192.0.2.10 443
    tls example.com 443
Exit code is 1 if any check fails. Uses only the standard library.
ICMP ping is not used because it needs raw sockets; TCP connect checks stand in for reachability.
"""
import socket
import ssl
import sys
import time
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


def run(lines):
    results = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        kind = parts[0]
        if kind == "dns" and len(parts) == 2:
            ok, msg, t = check_dns(parts[1])
        elif kind == "tcp" and len(parts) == 3:
            ok, msg, t = check_tcp(parts[1], int(parts[2]))
        elif kind == "tls" and len(parts) == 3:
            ok, msg, t = check_tls(parts[1], int(parts[2]))
        else:
            ok, msg, t = False, f"bad line: {line}", 0.0
        results.append((line, ok, msg, t))
    return results


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    with open(argv[1]) as f:
        results = run(f)
    for line, ok, msg, t in results:
        print(f'{"OK  " if ok else "FAIL"} {line:<30} {msg} ({t*1000:.0f} ms)')
    return 0 if all(r[1] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
