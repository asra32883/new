"""Browser end-to-end fixtures: a real uvicorn server (migrated with Alembic) and headless Chromium."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # browser binary missing
            pytest.skip(f"Chromium not available: {e}")
        yield b
        b.close()


@pytest.fixture
def server(tmp_path):
    port, db = _free_port(), tmp_path / "e2e.db"
    env = {
        **os.environ, "TORMAIL_ENV": "development", "TORMAIL_DATABASE_URL": f"sqlite:///{db}",
        "TORMAIL_COOKIE_SECURE": "false", "TORMAIL_SECRET_KEY": "e2e-" + "k" * 40, "TORMAIL_POW_DIFFICULTY_BITS": "12",
        "TORMAIL_ARGON2_TIME_COST": "1", "TORMAIL_ARGON2_MEMORY_KIB": "64", "TORMAIL_ARGON2_PARALLELISM": "1",
        "TORMAIL_SEND_PER_HOUR": "1000", "TORMAIL_SEND_PER_DAY": "1000",
    }
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, check=True, capture_output=True)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:factory", "--factory", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(base + "/healthz", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("server did not start: " + proc.stderr.read().decode())
    yield {"base": base, "db": db}
    proc.terminate()
    proc.wait(timeout=10)
