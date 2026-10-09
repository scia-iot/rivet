FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS dependencies
COPY deploy/locks/api.txt /opt/container/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/container/requirements.txt
FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
RUN groupadd --gid 65531 ovpn-control \
    && useradd --uid 65531 --gid 65531 --no-create-home ovpn-api \
    && mkdir -p /opt/rivet/certs /opt/rivet/profile \
    && chown -R 65531:65531 /opt/rivet
COPY --from=dependencies /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
# Runtime services never install packages; remove vendored installer payloads.
RUN python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip \
    && python -c "import importlib.util; assert all(importlib.util.find_spec(name) is None for name in ('pip', 'ensurepip'))"
COPY src/sciaiot /opt/app/sciaiot
COPY deploy/containers/api_entrypoint.py /opt/container/api_entrypoint.py
COPY deploy/containers/api_health.py /opt/container/api_health.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/app
USER 65531:65531
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["python", "/opt/container/api_health.py"]
ENTRYPOINT ["python", "/opt/container/api_entrypoint.py"]
