FROM python:3.11-slim-trixie@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

LABEL org.opencontainers.image.title="EggScan" \
      org.opencontainers.image.source="https://github.com/MRsnoken/EggScan" \
      org.opencontainers.image.licenses="GPL-3.0-only"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    EGGSCAN_CONTAINER=1 \
    EGGSCAN_DATA_DIR=/data

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iputils-ping \
        libcap2-bin \
        nmap \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 eggscan \
    && useradd --uid 10001 --gid eggscan --no-create-home --shell /usr/sbin/nologin eggscan \
    && install -d -o eggscan -g eggscan -m 0700 /data \
    && setcap cap_net_raw+eip /usr/bin/nmap \
    && setcap cap_net_raw+eip /usr/bin/ping

WORKDIR /app

COPY requirements.txt ./requirements.txt
COPY docker/requirements.lock ./docker/requirements.lock
RUN python -m pip install --no-cache-dir --upgrade 'pip>=26.2' 'setuptools>=84.1.0' \
    && pip install --no-cache-dir -r requirements.txt -r docker/requirements.lock \
    && pip check \
    && python -m pip uninstall --yes pip setuptools wheel

COPY eggscan.py version.json README.md CHANGELOG.md CONTRIBUTING.md LICENSE ./
COPY templates/ ./templates/
COPY static/ ./static/
COPY docker/entrypoint.py docker/healthcheck.py ./docker/
RUN chmod -R a=rX /app

USER 10001:10001

EXPOSE 5000

ENTRYPOINT ["python", "docker/entrypoint.py"]
CMD ["web"]
