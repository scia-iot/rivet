FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS build
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260920T000000Z/ trixie main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260920T000000Z/ trixie-security main' > /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev liblz4-dev liblzo2-dev libcap-ng-dev curl ca-certificates \
    && curl --fail --location --silent --show-error https://github.com/OpenVPN/openvpn/releases/download/v2.6.19/openvpn-2.6.19.tar.gz -o /tmp/openvpn.tar.gz \
    && echo '13702526f687c18b2540c1a3f2e189187baaa65211edcf7ff6772fa69f0536cf  /tmp/openvpn.tar.gz' | sha256sum -c - \
    && mkdir /tmp/openvpn && tar -xzf /tmp/openvpn.tar.gz --strip-components=1 -C /tmp/openvpn
WORKDIR /tmp/openvpn
RUN ./configure --prefix=/usr/local --disable-dco --disable-plugin-auth-pam --disable-systemd --disable-debug \
    && make -j2 && make install
FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260920T000000Z/ trixie main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260920T000000Z/ trixie-security main' > /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 libssl3t64 liblz4-1 liblzo2-2 libcap-ng0 \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 65532 ovpn-runtime \
    && groupadd --gid 65531 ovpn-control \
    && useradd --uid 65532 --gid 65532 --groups 65531 --no-create-home ovpn-agent \
    && useradd --uid 65530 --gid 65532 --no-create-home ovpn-openvpn
COPY --from=build /usr/local/sbin/openvpn /usr/local/sbin/openvpn
COPY deploy/locks/agent.txt /opt/agent/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/agent/requirements.txt
# Runtime services never install packages; remove vendored installer payloads.
RUN python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip \
    && python -c "import importlib.util; assert all(importlib.util.find_spec(name) is None for name in ('pip', 'ensurepip'))"
COPY src/sciaiot/rivet/application /opt/agent/sciaiot/rivet/application
COPY src/sciaiot/rivet/vpn_agent /opt/agent/sciaiot/rivet/vpn_agent
COPY src/sciaiot/rivet/adapters/vpn/settings.py /opt/agent/sciaiot/rivet/adapters/vpn/settings.py
COPY deploy/containers/openvpn_entrypoint.py /opt/container/openvpn_entrypoint.py
COPY deploy/containers/openvpn_health.py /opt/container/openvpn_health.py
COPY deploy/containers/vpn_event.sh /usr/local/bin/rivet-vpn-event
RUN chmod 0555 /usr/local/bin/rivet-vpn-event
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/agent
USER 0:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s CMD ["python", "/opt/container/openvpn_health.py"]
ENTRYPOINT ["python", "/opt/container/openvpn_entrypoint.py"]
