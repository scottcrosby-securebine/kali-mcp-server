ARG KALI_BASE_IMAGE=kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1
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

COPY docker/packages.lock /tmp/packages.lock

# The published image digest is the durable release artifact. Kali rolling may
# stop serving these exact package versions later, in which case a source
# rebuild fails instead of silently selecting newer packages.
RUN sed -i 's|http://http.kali.org/kali/|http://kali.download/kali/|' /etc/apt/sources.list.d/kali.sources \
    && apt-get -o Acquire::Retries=5 update \
    && xargs -r apt-get -o Acquire::Retries=5 install -y --no-install-recommends < /tmp/packages.lock \
    && while IFS='=' read -r package expected; do \
         actual="$(dpkg-query -W -f='${Version}' "${package}")"; \
         test "${actual}" = "${expected}" || { echo "${package}: expected ${expected}, got ${actual}" >&2; exit 1; }; \
       done < /tmp/packages.lock \
    && rm -rf /var/lib/apt/lists/*

COPY kali_pentest_server.py requirements.txt ./
COPY scripts/verify-image.sh /usr/local/bin/verify-kali-mcp-image

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin pentest \
    && chmod 0755 /usr/local/bin/verify-kali-mcp-image \
    && setcap -r /usr/lib/nmap/nmap

USER pentest

CMD ["python3", "kali_pentest_server.py"]
