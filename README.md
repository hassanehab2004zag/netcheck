# netcheck

A small network health checker in Python: DNS lookup, TCP port check and TLS certificate expiry.

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
```
Exit code is 1 if any check fails. Standard library only.

## Tests
```
python3 -m unittest discover -s tests
```
6 unit tests, passed on Python 3.10 in a local test environment. They run against local servers and a self-signed certificate: DNS for localhost and an invalid name, TCP open and closed ports, certificate valid, expiring and untrusted, and parsing of the targets file.

## Limits
Tested on local targets only. ICMP ping is not used because it needs raw sockets; a TCP connect check stands in for reachability. Not tested against real network devices.
