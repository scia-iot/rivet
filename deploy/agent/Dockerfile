FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS dependencies
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260920T000000Z/ trixie main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260920T000000Z/ trixie-security main' > /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables openssl ca-certificates curl \
    && curl --fail --location --silent --show-error https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.7/EasyRSA-3.1.7.tgz -o /tmp/easyrsa.tgz \
    && echo 'aaa48fadcbb77511b9c378554ef3eae09f8c7bc149d6f56ba209f1c9bab98c6e  /tmp/easyrsa.tgz' | sha256sum -c - \
    && mkdir -p /usr/share/easy-rsa \
    && tar -xzf /tmp/easyrsa.tgz --strip-components=1 -C /usr/share/easy-rsa \
    && rm /tmp/easyrsa.tgz && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/agent
COPY deploy/locks/agent.txt /opt/agent/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/agent/requirements.txt
FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260920T000000Z/ trixie main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260920T000000Z/ trixie-security main' > /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables openssl \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 65532 ovpn-runtime \
    && groupadd --gid 65531 ovpn-control \
    && useradd --uid 65532 --gid 65532 --groups 65531 --no-create-home ovpn-agent \
    && useradd --uid 65530 --gid 65532 --no-create-home ovpn-openvpn
WORKDIR /opt/agent
COPY --from=dependencies /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
# Runtime services never install packages; remove vendored installer payloads.
RUN python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip \
    && python -c "import importlib.util; assert all(importlib.util.find_spec(name) is None for name in ('pip', 'ensurepip'))"
COPY --from=dependencies /usr/share/easy-rsa /usr/share/easy-rsa
COPY src/sciaiot/rivet/application /opt/agent/sciaiot/rivet/application
COPY src/sciaiot/rivet/vpn_agent /opt/agent/sciaiot/rivet/vpn_agent
COPY src/sciaiot/rivet/adapters/vpn/settings.py /opt/agent/sciaiot/rivet/adapters/vpn/settings.py
COPY deploy/containers/agent_health.py /opt/agent/agent_health.py
COPY deploy/containers/agent_bootstrap.py /opt/agent/agent_bootstrap.py
USER 0:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=12s --start-period=30s CMD ["python", "-I", "/opt/agent/agent_bootstrap.py", "--health"]
ENTRYPOINT ["python", "-I", "/opt/agent/agent_bootstrap.py"]
