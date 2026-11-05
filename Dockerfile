# syntax=docker/dockerfile:1
# u2-mcp in team mode. Two targets:
#   release - what you deploy (no test code)
#   test    - adds the scripted U2 driver and the mock identity provider, for CI's
#             browser tests (U2_E2E_IMAGE); never deploy it.

# pip is needed only to install; the builder's pip fills a venv that has none.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# uopy (Rocket's driver) is on PyPI, so this installs everything the server needs.
RUN python -m venv --without-pip /opt/venv \
    && pip --python /opt/venv/bin/python install .
# Stamp the commit for the admin footer, read from the context's .git files
# (.dockerignore lets only HEAD and the refs through). Empty when there are none.
RUN --mount=type=bind,source=.,target=/ctx /opt/venv/bin/python -m u2_mcp.version /ctx

FROM python:3.12-slim AS release

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

COPY --from=builder /opt/venv /opt/venv
# The runtime image carries no pip (or its bundled wheel), so no pip CVEs.
RUN rm -rf /usr/local/bin/pip* \
        /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.12/site-packages/setuptools* \
        /usr/local/lib/python3.12/site-packages/wheel* \
        /usr/local/lib/python3.12/ensurepip/_bundled \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin u2mcp \
    && mkdir -p /data \
    && chown -R u2mcp /data

# /data is the one volume: the settings database (with its -wal and -shm files)
# and, because uopy logs to ./logs and reads ./uopy.ini, the driver's log too.
ENV U2_DATA_DIR=/data \
    U2_HTTP_HOST=0.0.0.0 \
    U2_HTTP_PORT=8000
VOLUME ["/data"]
WORKDIR /data
EXPOSE 8000
USER u2mcp

# slim has no curl: ask /health with Python. https when U2_TLS_CERT is set.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, ssl, urllib.request; s = 'https' if os.environ.get('U2_TLS_CERT') else 'http'; p = os.environ.get('U2_HTTP_PORT', '8000'); urllib.request.urlopen(s + '://127.0.0.1:' + p + '/health', timeout=4, context=ssl._create_unverified_context())"

ENTRYPOINT ["u2-mcp"]
CMD ["--streamable-http"]

FROM release AS test
USER root
COPY tests/__init__.py /app/tests/__init__.py
COPY tests/mocks /app/tests/mocks
ENV PYTHONPATH=/app \
    U2_DRIVER=tests.mocks.sim_driver
USER u2mcp
