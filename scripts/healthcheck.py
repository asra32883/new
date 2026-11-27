"""Container health probe: asks the app for /healthz over its Unix socket (there is no TCP listener)."""
import socket
import sys

SOCKET = sys.argv[1] if len(sys.argv) > 1 else "/run/tormail/app.sock"

try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect(SOCKET)
    s.sendall(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
    ok = s.recv(64).startswith(b"HTTP/1.1 200")
except OSError:
    ok = False
sys.exit(0 if ok else 1)
