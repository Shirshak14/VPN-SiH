FROM debian:bookworm-slim

# strongSwan 5.9 with the legacy crypto plugins we need to *deliberately* build weak
# tunnels (DES/3DES/MD5/MODP768). Lab use only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      strongswan strongswan-charon strongswan-swanctl \
      libstrongswan-standard-plugins libstrongswan-extra-plugins \
      libcharon-extra-plugins libcharon-extauth-plugins \
      tcpdump iproute2 iputils-ping procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY charon-logging.conf /etc/strongswan.d/charon-logging.conf
CMD ["sleep", "infinity"]
