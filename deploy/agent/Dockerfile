# Phase 3 development image. Digest/signature/SBOM gates belong to Phase 5.
FROM python:3.14-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 65532 ovpn-runtime && useradd --uid 65532 --gid 65532 --no-create-home ovpn-agent
RUN pip install --no-cache-dir pydantic cryptography
WORKDIR /opt/agent
COPY src/sciaiot/ovpncp/application /opt/agent/sciaiot/ovpncp/application
COPY src/sciaiot/ovpncp/vpn_agent /opt/agent/sciaiot/ovpncp/vpn_agent
COPY src/sciaiot/ovpncp/adapters/vpn/settings.py /opt/agent/sciaiot/ovpncp/adapters/vpn/settings.py
# Deployment overrides to its explicitly allocated agent UID/runtime GID.
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "sciaiot.ovpncp.vpn_agent.cli"]
