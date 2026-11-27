# Tor-Mail application image. Runs as an unprivileged user, serves HTTP on the internal Docker network only.
# For production, pin the base image by digest:  FROM python:3.13-slim@sha256:<digest>
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# gid 10002 is shared with the Tor container (compose group_add) so it can reach the app's Unix socket.
RUN groupadd --system --gid 10002 tormail && \
    useradd --system --uid 10001 --gid 10002 --no-create-home --shell /usr/sbin/nologin tormail && \
    install -d -o 10001 -g 10002 -m 0750 /run/tormail
WORKDIR /srv/tormail

COPY requirements.lock .
RUN pip install --require-hashes --no-deps -r requirements.lock

COPY alembic.ini ./
COPY migrations ./migrations
COPY scripts ./scripts
COPY app ./app

USER 10001

# The app listens ONLY on a Unix socket inside /run/tormail (a volume shared read-only with the Tor container).
# There is no TCP listener, so the HTTP hop between Tor and the app never touches a network: Tor Browser returns
# "Secure" cookies over plain-HTTP onion connections, so that hop must not be a network hop.
# uvicorn creates the socket world-writable; access is controlled by the directory (0750, group 10002).
ENV TORMAIL_ENV=production

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD ["python", "/srv/tormail/scripts/healthcheck.py", "/run/tormail/app.sock"]

# Access logging is off by default: request logs would hold paths and timing for every user.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:factory --factory --uds /run/tormail/app.sock --no-access-log --no-server-header"]
