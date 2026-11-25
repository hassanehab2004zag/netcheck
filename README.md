# netcheck

A small network health checker in Python: DNS lookup, TCP port check, TLS certificate expiry and HTTP status check.

Practice project on test data. Not company work.

## Usage
```
python3 netcheck.py targets.txt
```
`targets.txt`, one check per line:
```
dns example.com
tcp 192.0.2.10 443
tls example.com 443
http http://example.com 200
```
Options: `--json` for machine-readable output, `--workers N` to run checks in parallel (default 4, output keeps file order), `--warn-days N` for the TLS expiry threshold (default 14). The `http` check does not follow redirects, so a 301 can be asserted as expected.
Exit code is 1 if any check fails. Standard library only.

## Example run
Against a local web server (`python3 -m http.server 8765`) and local ports, with this `targets.txt`:
```
dns localhost
tcp 127.0.0.1 8765
http http://127.0.0.1:8765/ 200
http http://127.0.0.1:8765/missing 200
tcp 127.0.0.1 9
```
Output (exit code 1 because two checks fail on purpose):
```
OK   dns localhost                  resolved to 127.0.0.1 (4 ms)
OK   tcp 127.0.0.1 8765             port open (0 ms)
OK   http http://127.0.0.1:8765/ 200 status 200 (4 ms)
FAIL http http://127.0.0.1:8765/missing 200 status 404, expected 200 (5 ms)
FAIL tcp 127.0.0.1 9                connect failed: [Errno 111] Connection refused (0 ms)
```

## Tests
```
python3 -m unittest discover -s tests
```
12 unit tests, passed on Python 3.10 in a local test environment. They run against local servers and a self-signed certificate: DNS for localhost and an invalid name, TCP open and closed ports, certificate valid, expiring and untrusted, HTTP status match, mismatch, redirect and refused connection against a local server, parallel run order, JSON output with exit code, and parsing of the targets file.

## Limits
Tested on local targets only. ICMP ping is not used because it needs raw sockets; a TCP connect check stands in for reachability. Not tested against real network devices.
