# Tor daemon that publishes the onion service. Pin by digest in production.
FROM alpine:3.21

RUN apk add --no-cache tor && \
    install -d -o tor -g tor -m 0700 /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=10 \
    CMD test -s /var/lib/tor/tormail/hostname

CMD ["tor", "-f", "/etc/tor/torrc"]
