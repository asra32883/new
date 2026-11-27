"""Static checks of the deployment files. They cannot prove a running stack is safe, but they stop the
properties the privacy design depends on from silently regressing."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
NETWORKS = COMPOSE["networks"]
TORRC = (ROOT / "tor" / "torrc").read_text()
APP_DOCKERFILE = (ROOT / "Dockerfile").read_text()
TOR_DOCKERFILE = (ROOT / "tor" / "Dockerfile").read_text()


def torrc_options():
    out = {}
    for line in TORRC.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition(" ")
            out.setdefault(key, []).append(value.strip())
    return out


# ---- network exposure ----------------------------------------------------------------------------------


def test_no_service_publishes_a_host_port():
    for name, svc in SERVICES.items():
        assert "ports" not in svc, f"{name} publishes ports"
        assert svc.get("network_mode") not in ("host",), f"{name} uses host networking"
        assert not svc.get("privileged"), f"{name} is privileged"


def test_network_topology_isolates_app_and_database():
    nets = {n: set(s["networks"]) for n, s in SERVICES.items()}
    assert nets["db"] == {"backend"} and nets["app"] == {"backend"}
    assert nets["tor"] == {"egress"}                       # tor shares no network with the app at all
    assert NETWORKS["backend"]["internal"] is True
    assert not NETWORKS["egress"].get("internal")
    # the only service with a route to the internet is tor
    for name in ("app", "db"):
        assert all(NETWORKS[n].get("internal") for n in nets[name]), f"{name} can reach the internet"


def test_tor_reaches_the_app_only_through_a_read_only_socket_volume():
    app_vols = [v for v in SERVICES["app"]["volumes"] if v.startswith("appsock:")]
    tor_vols = [v for v in SERVICES["tor"]["volumes"] if v.startswith("appsock:")]
    assert app_vols == ["appsock:/run/tormail"] or app_vols[0].split(":")[:2] == ["appsock", "/run/tormail"]
    assert len(tor_vols) == 1 and tor_vols[0].endswith(":ro") and tor_vols[0].split(":")[1] == "/run/tormail"
    assert "appsock" in COMPOSE["volumes"]
    # tor joins the app's group so it can traverse the 0750 socket directory; nothing else shares that group
    gid = re.search(r"--gid (\d+) tormail", APP_DOCKERFILE).group(1)
    assert SERVICES["tor"]["group_add"] == [gid]
    assert "group_add" not in SERVICES["db"]
    assert re.search(rf"install -d -o 10001 -g {gid} -m 0750 /run/tormail", APP_DOCKERFILE)


def test_containers_are_locked_down():
    for name, svc in SERVICES.items():
        assert svc["read_only"] is True, name
        assert "ALL" in svc["cap_drop"], name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert svc.get("pids_limit"), name
    assert set(SERVICES["app"].get("cap_add", [])) == set() and set(SERVICES["tor"].get("cap_add", [])) == set()


def test_no_secrets_in_compose():
    env = SERVICES["app"]["environment"]
    assert env["TORMAIL_SECRET_KEY"].startswith("${")
    assert "${POSTGRES_PASSWORD" in env["TORMAIL_DATABASE_URL"]
    assert SERVICES["db"]["environment"]["POSTGRES_PASSWORD"].startswith("${")
    assert ":?" in SERVICES["app"]["environment"]["TORMAIL_SECRET_KEY"]       # compose refuses to start without it
    assert ":?" in SERVICES["db"]["environment"]["POSTGRES_PASSWORD"]


def test_app_runs_in_production_mode_with_secure_cookies():
    env = SERVICES["app"]["environment"]
    assert env["TORMAIL_ENV"] == "production" and env["TORMAIL_COOKIE_SECURE"] == "true"
    assert env["TORMAIL_DATABASE_URL"].startswith("postgresql")


def test_compose_resolves_with_the_docker_cli():
    if not shutil.which("docker"):
        pytest.skip("docker CLI not installed")
    env = {**os.environ, "POSTGRES_PASSWORD": "ab" * 24, "TORMAIL_SECRET_KEY": "k" * 48}
    res = subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=ROOT, env=env, capture_output=True, text=True)
    if res.returncode != 0 and "compose" in res.stderr and "not a docker command" in res.stderr:
        pytest.skip("docker compose plugin missing")
    assert res.returncode == 0, res.stderr
    resolved = json.loads(res.stdout)
    assert all("ports" not in s for s in resolved["services"].values())
    assert resolved["networks"]["backend"]["internal"] and "onion" not in resolved["networks"]
    assert resolved["services"]["tor"]["networks"].keys() == {"egress"}
    assert resolved["services"]["app"]["networks"].keys() == {"backend"}


def test_compose_refuses_to_start_without_secrets():
    if not shutil.which("docker"):
        pytest.skip("docker CLI not installed")
    env = {k: v for k, v in os.environ.items() if k not in ("POSTGRES_PASSWORD", "TORMAIL_SECRET_KEY")}
    res = subprocess.run(["docker", "compose", "config"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert res.returncode != 0 and "required variable" in res.stderr


# ---- Tor configuration ---------------------------------------------------------------------------------


def test_torrc_publishes_a_v3_service_to_the_app_socket():
    opts = torrc_options()
    assert opts["HiddenServiceVersion"] == ["3"]
    # Local Unix socket only: Tor Browser returns "Secure" cookies over plain-HTTP onion connections, so the
    # hop between Tor and the app must never cross a network.
    assert opts["HiddenServicePort"] == ["80 unix:/run/tormail/app.sock"]
    assert opts["HiddenServiceDir"][0].startswith("/var/lib/tor/")
    volume_targets = [v.split(":")[1] for v in SERVICES["tor"]["volumes"]]
    assert "/var/lib/tor" in volume_targets                    # identity key persists across restarts


def test_app_listens_only_on_the_socket_tor_forwards_to():
    sock = torrc_options()["HiddenServicePort"][0].split("unix:")[1]
    assert f"--uds {sock}" in APP_DOCKERFILE
    cmd = APP_DOCKERFILE[APP_DOCKERFILE.index("CMD"):]
    assert "--port" not in cmd and "--host" not in cmd         # no TCP listener at all
    assert "scripts/healthcheck.py" in APP_DOCKERFILE and "TORMAIL_INTERNAL_NETWORK_ACK" not in APP_DOCKERFILE


def test_torrc_is_not_a_relay_or_proxy_and_has_no_control_surface():
    opts = torrc_options()
    assert opts["SocksPort"] == ["0"] and opts["ClientOnly"] == ["1"] and opts["ExitRelay"] == ["0"]
    for forbidden in ("ControlPort", "ControlSocket", "CookieAuthentication", "ORPort", "DirPort", "HTTPTunnelPort",
                      "TransPort", "DNSPort", "HiddenServiceNonAnonymousMode", "HiddenServiceSingleHopMode"):
        assert forbidden not in opts, f"torrc must not set {forbidden}"
    # legacy v2 services must never come back
    assert "HiddenServiceVersion 2" not in TORRC


def test_torrc_enables_dos_defences_and_never_logs_to_disk():
    opts = torrc_options()
    assert opts["HiddenServiceEnableIntroDoSDefense"] == ["1"]
    assert opts["HiddenServicePoWDefensesEnabled"] == ["1"]
    assert int(opts["HiddenServiceMaxStreams"][0]) > 0 and opts["HiddenServiceMaxStreamsCloseCircuit"] == ["1"]
    assert opts["Log"] == ["notice stdout"]                    # not "debug", not a file


# ---- images ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("text", [APP_DOCKERFILE, TOR_DOCKERFILE], ids=["app", "tor"])
def test_images_use_pinned_tags_and_run_unprivileged(text):
    froms = re.findall(r"^FROM\s+(\S+)", text, re.M)
    assert froms and all(":" in f and not f.endswith(":latest") for f in froms)
    user = re.findall(r"^USER\s+(\S+)", text, re.M)
    assert user and user[-1] not in ("root", "0")


def test_app_image_disables_access_logs_and_server_header():
    assert "--no-access-log" in APP_DOCKERFILE and "--no-server-header" in APP_DOCKERFILE
    assert "--reload" not in APP_DOCKERFILE and "--proxy-headers" not in APP_DOCKERFILE
    assert "COPY .env" not in APP_DOCKERFILE and "COPY tests" not in APP_DOCKERFILE


def test_dockerignore_keeps_secrets_out_of_images():
    ignored = (ROOT / ".dockerignore").read_text().split()
    for item in (".env", "*.db", ".git", "hs_ed25519_secret_key"):
        assert item in ignored


def test_gitignore_protects_onion_keys_and_env():
    ignored = (ROOT / ".gitignore").read_text().split()
    for item in (".env", "hs_ed25519_secret_key", "hs_ed25519_public_key", "*.db"):
        assert item in ignored


def test_container_bind_requires_explicit_acknowledgement():
    from app.config import ConfigError, Settings
    base = dict(_env_file=None, env="production", secret_key="k" * 40, database_url="postgresql://u:p@db/x", bind_host="0.0.0.0")
    os.environ.pop("TORMAIL_INTERNAL_NETWORK_ACK", None)
    with pytest.raises(Exception, match="BIND_HOST"):
        Settings(**base)


# ---- the application itself never reaches out --------------------------------------------------------------


def test_application_code_makes_no_outbound_connections():
    banned = re.compile(r"^\s*(import|from)\s+(requests|httpx|aiohttp|urllib3|urllib\.request|http\.client|smtplib|ftplib|"
                        r"telnetlib|socket|dns|boto3|sentry_sdk)\b", re.M)
    for path in (ROOT / "app").rglob("*.py"):
        assert not banned.search(path.read_text()), f"{path.relative_to(ROOT)} imports a network client"


def test_no_third_party_origins_in_our_templates_and_scripts():
    own = [p for p in (ROOT / "app").rglob("*") if p.is_file() and p.suffix in (".html", ".js", ".css")
           and "vendor" not in p.parts]
    assert own
    for p in own:
        for url in re.findall(r"https?://[^\s\"')]+", p.read_text()):
            # same-origin documentation links are not allowed to point anywhere external either
            assert False, f"{p.relative_to(ROOT)} references external URL {url}"
