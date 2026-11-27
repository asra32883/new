#!/usr/bin/env bash
# Run on the Docker host after `docker compose up -d`. Verifies the properties the privacy design depends on.
# Exits non-zero if any check fails. Read-only: changes nothing.
set -u
cd "$(dirname "$0")/.."
fail=0
ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

echo "1. No container publishes a host port"
published=$(docker ps --filter label=com.docker.compose.project=tormail --format '{{.Names}} {{.Ports}}' | grep -- '->' || true)
if [ -z "$published" ]; then ok "no published ports"; else bad "published ports found:"; echo "$published"; fi

echo "2. The app container cannot reach the internet"
if docker compose exec -T app python -c "import socket; socket.create_connection(('1.1.1.1', 443), 4)" >/dev/null 2>&1; then
  bad "app opened an outbound connection"
else ok "outbound connection from app failed"; fi

echo "3. The app has no TCP listener (only its Unix socket)"
listeners=$(docker compose exec -T app python -c "
for f in ('/proc/net/tcp', '/proc/net/tcp6'):
    try:
        print(sum(1 for l in open(f).read().splitlines()[1:] if l.split()[3] == '0A'))
    except OSError:
        print(0)
" 2>/dev/null | tr '\n' ' ')
if [ "$listeners" = "0 0 " ]; then ok "no TCP listening sockets in the app container"; else bad "TCP listeners present (counts v4 v6: $listeners)"; fi

echo "4. The database is not reachable from the Tor container"
if docker compose exec -T tor sh -c "nc -z -w 3 db 5432" >/dev/null 2>&1; then bad "tor can reach db:5432"; else ok "tor cannot reach the database"; fi

echo "5. The onion service is published"
host=$(docker compose exec -T tor cat /var/lib/tor/tormail/hostname 2>/dev/null | tr -d '\r\n')
if [[ "$host" =~ ^[a-z2-7]{56}\.onion$ ]]; then ok "v3 onion address: $host"; else bad "no valid v3 onion hostname yet (check: docker compose logs tor)"; fi

echo "6. Informational: TCP ports listening on this host (none of them should be Tor-Mail)"
ss -tlnH 2>/dev/null | awk '{print "        " $4}' | sort -u

exit $fail
