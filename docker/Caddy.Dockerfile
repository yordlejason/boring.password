FROM caddy:2-alpine
# All configured ports are unprivileged. Remove the vendor file capability so
# non-root execution works with cap_drop:ALL and no-new-privileges unchanged.
RUN setcap -r /usr/bin/caddy
USER 1000:1000
