# Rivet

An OpenVPN control plane for restricted IoT and edge networks. Rivet provides
a REST API, web UI, and private VPN agent for client certificates, fixed
addresses, routes, and controlled access between VPN peers.

[![Tests](https://github.com/scia-iot/rivet/actions/workflows/tests.yml/badge.svg)](https://github.com/scia-iot/rivet/actions/workflows/tests.yml)
[![CodeQL](https://github.com/scia-iot/rivet/actions/workflows/codeql.yml/badge.svg)](https://github.com/scia-iot/rivet/actions/workflows/codeql.yml)
[![Package](https://github.com/scia-iot/rivet/actions/workflows/package.yml/badge.svg)](https://github.com/scia-iot/rivet/actions/workflows/package.yml)

## Install

Both deployment options use an unprivileged API and a separate privileged
agent on Linux. OpenVPN continues forwarding traffic during an API outage.

| Deployment | Packages or images | Guide |
| --- | --- | --- |
| Native Linux | `sciaiot-rivet[api]` and `sciaiot-rivet-agent` in separate Python 3.14+ environments | [Native installation](docs/deployment.md#native-installation) |
| Docker Compose | `rivet-api`, `rivet-agent`, `rivet-openvpn`, `rivet-web` from your registry | [Container deployment](docs/deployment.md#container-deployment) |

The API command is `rivet`; the agent command is `rivet-agent`. Do not install
the unrelated PyPI package `rivet`. Installing a wheel alone does not provision
OpenVPN or the browser UI; follow the complete installation guide.

Builds and deployments are provider-independent. The supplied authenticated
API/UI configuration uses Microsoft Entra ID. Azure Blob Storage is optional.
SQLite is the reference database; extras support MySQL and PostgreSQL.
See [configuration](docs/configuration.md) and
[production deployment](docs/deployment.md#production-ingress-and-verification) for identity, HTTPS,
network, and release requirements.

Package/image publication and deployment acceptance requirements are tracked
in [release readiness](docs/builds.md#release-verification).

## Use

Start with the [user guide](docs/user-guide.md) to register clients, assign
addresses, distribute credentials, and manage restricted networks. A device
AccessGrant controls application visibility; a restricted network controls
VPN traffic. They are separate policies.

The API exposes its schema at `/openapi.json` and interactive reference at
`/docs` (under `/api` through Nginx). Management calls require the appropriate
verified permission. See [API authorization and agent mapping](docs/vpn-control.md#api-route-mapping).

For existing VPN installations, use the [migration toolkit](docs/data-management.md#openvpn-migration).
Whole-application backups use the [backup and recovery section](docs/data-management.md#backup-and-recovery).

## Develop

See [local development](docs/deployment.md#local-development) for Python setup, the
authenticated API/agent stack, and isolated UI testing. Frontend commands and
implementation conventions live in [frontend/README.md](frontend/README.md).

From an environment with `requirements-dev.txt` installed:

```bash
ruff format --check .
ruff check .
mypy .
pytest --cov=src/sciaiot/rivet --cov-report=term-missing
```

Ordinary tests mock privileged operations and cloud services. Live VPN tests
are explicitly invoked on disposable Linux infrastructure; see the
[integration harness guide](tests/integration/README-container.md).

The [documentation index](docs/README.md) links current operational and
engineering references, including the [architecture](docs/architecture.md#components-and-boundaries).
