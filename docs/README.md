# Rivet documentation

Each guide covers one main topic, with deployment variants and related
procedures grouped into sections.

| Topic | Sections |
| --- | --- |
| [Deployment](deployment.md) | [Local development](deployment.md#local-development), [native installation](deployment.md#native-installation), [containers](deployment.md#container-deployment), [production ingress and verification](deployment.md#production-ingress-and-verification) |
| [Configuration](configuration.md) | API/agent settings, Entra roles, browser settings, database/Blob secrets, shared profiles |
| [Architecture](architecture.md) | Components, trust boundaries, persistent state, application backends |
| [VPN control](vpn-control.md) | Agent operation, protocol, API permissions and route mapping |
| [Builds and releases](builds.md) | Container/Python/UI artifacts, local/Azure/GitHub builds, publishing, release checks |
| [Migration and recovery](data-management.md) | OpenVPN import/export, target mapping, encryption, whole-application backup and restore |
| [Usage](user-guide.md) | Client registration, credentials, ownership, device grants, restricted networks, retirement |

Source-specific development details remain beside their code: the
[frontend README](../frontend/README.md) covers browser implementation and
[the integration README](../tests/integration/README-container.md) covers
explicitly invoked live test harnesses.

Completed transition documents are in the [archive](archive/README.md).
Superseded plans and verification logs remain in Git history.

Proposed work: [provider-independent storage and authentication](cloud-services-plan.md).
