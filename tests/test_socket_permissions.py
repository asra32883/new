"""Real-process test of the access model the Tor<->app Unix socket relies on.

uvicorn creates the socket world-writable, so the *directory* is the lock: owned by the app (uid 10001),
group 10002, mode 0750. A process in group 10002 (the tor container) can connect; any other user cannot.
Needs root and `setpriv`, so it is skipped elsewhere.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("setpriv"), reason="needs root and setpriv")

PROBE = """
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(3)
try:
    s.connect(sys.argv[1]); s.sendall(b"GET /healthz HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n")
    print("OK" if s.recv(64).startswith(b"HTTP/1.1 200") else "BAD")
except PermissionError: print("DENIED")
except OSError as e: print("ERR " + type(e).__name__)
"""


@pytest.fixture
def sockdir():
    base = Path(tempfile.mkdtemp(dir="/var/tmp"))
    base.chmod(0o755)
    run, data = base / "run", base / "data"
    run.mkdir(); data.mkdir()
    for d in (run, data):
        os.chown(d, 10001, 10002)
    run.chmod(0o750)
    yield base
    shutil.rmtree(base, ignore_errors=True)


def probe(sockpath, uid, groups):
    group_args = ["--groups", groups] if groups else ["--clear-groups"]
    out = subprocess.run(["setpriv", "--reuid", str(uid), "--regid", str(uid), *group_args, sys.executable, "-I", "-c", PROBE, str(sockpath)],
                         capture_output=True, text=True, timeout=10)
    return out.stdout.strip() or out.stderr.strip()


def launch(base):
    env = {**os.environ, "TORMAIL_ENV": "development", "TORMAIL_DATABASE_URL": f"sqlite:///{base}/data/t.db"}
    return subprocess.Popen(
        ["setpriv", "--reuid", "10001", "--regid", "10002", "--clear-groups", sys.executable, "-m", "uvicorn", "app.main:factory",
         "--factory", "--uds", str(base / "run" / "app.sock"), "--no-access-log"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def wait_up(base, proc):
    sock = base / "run" / "app.sock"
    for _ in range(80):
        if proc.poll() is not None:
            pytest.skip("server could not start as an unprivileged user here: " + proc.stderr.read().decode()[-200:])
        if probe(sock, 10003, "10002") == "OK":
            return
        time.sleep(0.25)
    pytest.fail("app never answered on its socket")


def test_only_the_tor_group_can_reach_the_app_socket(sockdir):
    sock = sockdir / "run" / "app.sock"
    proc = launch(sockdir)
    try:
        wait_up(sockdir, proc)
        assert probe(sock, 10001, "10002") == "OK"          # the app's own user
        assert probe(sock, 10003, "10002") == "OK"          # tor: unprivileged user in the shared group
        assert probe(sock, 10004, "10004") == "DENIED"      # any other user on the machine
        assert probe(sock, 10005, "") == "DENIED"           # a user with no groups at all
        assert (os.stat(sockdir / "run").st_mode & 0o777) == 0o750
    finally:
        proc.kill(); proc.wait()


def test_restart_over_a_stale_socket_recovers(sockdir):
    sock = sockdir / "run" / "app.sock"
    first = launch(sockdir)
    try:
        wait_up(sockdir, first)
    finally:
        first.kill(); first.wait()                           # SIGKILL leaves the socket file behind
    assert sock.exists() and probe(sock, 10003, "10002").startswith("ERR")   # stale: nothing listens
    second = launch(sockdir)
    try:
        wait_up(sockdir, second)
        assert probe(sock, 10004, "10004") == "DENIED"
    finally:
        second.kill(); second.wait()
