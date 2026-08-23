ARG KALI_BASE_IMAGE=kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1
FROM ${KALI_BASE_IMAGE} AS source-tool-builder

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src

RUN sed -i 's/Types: deb/Types: deb deb-src/' /etc/apt/sources.list.d/kali.sources \
    && sed -i 's|http://http.kali.org/kali/|http://kali.download/kali/|' /etc/apt/sources.list.d/kali.sources \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
         build-essential=12.12 dpkg-dev=1.23.7+kali1 debhelper=14.3 \
         libcurl4-openssl-dev=8.21.0-2 libssl-dev=3.6.3-1 \
    && apt-get source --download-only dirb=2.22+dfsg-7 sslscan=2.1.5-1 nbtscan=1.7.2-3 \
    && printf '%s  %s\n' \
         '9a2aea6e82e12ee03ff4b4c17d831bca3ca116dab4a415eda13849c7db6833f6' 'dirb_2.22+dfsg-7.dsc' \
         'fb24f2e3b33f6e752395c3e090e26aa5f500202c97ca65993415187f20d1541a' 'dirb_2.22+dfsg.orig.tar.gz' \
         '97dfd5ec934167e35bc300d26864c2cc5cba72d862c9d10ca8594f4b73e07283' 'dirb_2.22+dfsg-7.debian.tar.xz' \
         '05876de61b58e1ada207e44aeacffbedcecf86975c65b27be3a747baffba76b3' 'sslscan_2.1.5-1.dsc' \
         'b36616b1d59f3276af6ff9495ab8178ec6812393582fb3c094c56cc873efe956' 'sslscan_2.1.5.orig.tar.gz' \
         'd8516642b5cd53ac24d3793c52c23244a39efbe24aa56df9658c2c91b3349e08' 'sslscan_2.1.5-1.debian.tar.xz' \
         'dbcb71ecb3b5df51de63075251402e68146089881193259054ad70971505320a' 'nbtscan_1.7.2-3.dsc' \
         '00e61be7c05cd3a34d5fefedffff86dc6add02d4c728b22e13fb9fbeabba1984' 'nbtscan_1.7.2.orig.tar.gz' \
         '43b066df29ac935cdbcf3ea21195c8b28ca8f8ce5b7b28967f02addb52c6e97d' 'nbtscan_1.7.2-3.debian.tar.xz' \
       | sha256sum -c - \
    && dpkg-source -x dirb_2.22+dfsg-7.dsc \
    && dpkg-source -x sslscan_2.1.5-1.dsc \
    && dpkg-source -x nbtscan_1.7.2-3.dsc \
    && (cd dirb-2.22+dfsg && dpkg-buildpackage -us -uc -b) \
    && (cd sslscan-2.1.5 && dpkg-buildpackage -us -uc -b) \
    && (cd nbtscan-1.7.2 && dpkg-buildpackage -us -uc -b) \
    && mkdir /packages \
    && find /src -maxdepth 1 -type f \( -name 'dirb_*_*.deb' -o -name 'sslscan_*_*.deb' -o -name 'nbtscan_*_*.deb' \) ! -name '*dbgsym*' -exec cp '{}' /packages/ \;

FROM ${KALI_BASE_IMAGE}

ARG KALI_BASE_IMAGE
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Kali MCP Server" \
      org.opencontainers.image.source="https://github.com/scottcrosby-securebine/kali-mcp-server" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="${KALI_BASE_IMAGE}"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY docker/packages.lock docker/source-packages.lock /tmp/
COPY --from=source-tool-builder /packages/ /tmp/source-packages/

# The published image digest is the durable release artifact. Kali rolling may
# stop serving these exact package versions later, in which case a source
# rebuild fails instead of silently selecting newer packages.
RUN sed -i 's|http://http.kali.org/kali/|http://kali.download/kali/|' /etc/apt/sources.list.d/kali.sources \
    && apt-get -o Acquire::Retries=5 update \
    && xargs -r apt-get -o Acquire::Retries=5 install -y --no-install-recommends < /tmp/packages.lock \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends /tmp/source-packages/*.deb \
    && while IFS='=' read -r package expected; do \
         actual="$(dpkg-query -W -f='${Version}' "${package}")"; \
         test "${actual}" = "${expected}" || { echo "${package}: expected ${expected}, got ${actual}" >&2; exit 1; }; \
       done < /tmp/packages.lock \
    && while IFS='=' read -r package expected; do \
         actual="$(dpkg-query -W -f='${Version}' "${package}")"; \
         test "${actual}" = "${expected}" || { echo "${package}: expected ${expected}, got ${actual}" >&2; exit 1; }; \
       done < /tmp/source-packages.lock \
    && rm -rf /var/lib/apt/lists/*

COPY kali_pentest_server.py requirements.txt ./
COPY tests/fixtures/legacy_tool_contract.json /usr/local/share/kali-mcp/legacy_tool_contract.json
COPY docker/packages.lock /usr/local/share/kali-mcp/packages.lock
COPY docker/source-packages.lock /usr/local/share/kali-mcp/source-packages.lock
COPY nuclei-templates /usr/local/share/kali-mcp/nuclei-templates
COPY scripts/verify-image.sh /usr/local/bin/verify-kali-mcp-image

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin pentest \
    && chmod 0755 /usr/local/bin/verify-kali-mcp-image \
    && setcap -r /usr/lib/nmap/nmap

USER pentest

CMD ["python3", "kali_pentest_server.py"]
