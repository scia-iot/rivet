# Archived: architecture upgrade status

> Historical phase-status snapshot, archived on 2026-10-09. This is not an
> active implementation plan. Use [architecture](../architecture.md#components-and-boundaries) for the
> current design and [release readiness](../builds.md#release-verification) for open work.

Core architecture through Phase 7, native packaging, and the Rivet rename are
implemented. The current design is described in [architecture](../architecture.md#components-and-boundaries);
installation instructions live in the [documentation index](../README.md).
This page retains phase status without duplicating implementation diaries.

| Phase / track | Status | Current reference |
| --- | --- | --- |
| M0: portable OpenVPN migration | Implemented; stopped generic and container target profiles | [Migration](../data-management.md#openvpn-migration) |
| 0: architecture and threat boundaries | Implemented in the reference deployment | [Architecture](../architecture.md#components-and-boundaries) |
| 1: application interface and protocol | Implemented | [Protocol](../vpn-control.md#control-protocol), [route matrix](../vpn-control.md#api-route-mapping) |
| 2: API seam and compatibility adapters | Implemented | [Backends](../architecture.md#application-backends) |
| 3: observation and shadow comparison | Implemented | [Agent](../vpn-control.md#agent-operation) |
| 4: privileged mutations and durable recovery | Implemented; families explicitly enabled | [Agent](../vpn-control.md#agent-operation) |
| 5: images and portable builds | Implemented; release verification deferred | [Builds](../builds.md#build-and-publish-artifacts), [release readiness](../builds.md#release-verification) |
| 6: Compose reference | Implemented; isolated and actual-topology predecessor checks passed | [Container deployment](../deployment.md#container-deployment) |
| 7: migration and recovery | Migration implementation and test cutover completed; coordinated same-host restore verified on predecessor artifacts; remaining production/off-host acceptance operator-owned | [Migration](../data-management.md#openvpn-migration), [recovery](../data-management.md#backup-and-recovery) |
| 8: Azure edge and network | Deferred to the real deployment's requirements | [Production deployment](../deployment.md#production-ingress-and-verification) |
| 9: production cutover | Deferred to the real deployment | [Production deployment](../deployment.md#production-ingress-and-verification), [recovery](../data-management.md#backup-and-recovery) |
| 10: high availability | Optional future deployment work, not implemented by this reference | [Architecture](../architecture.md#components-and-boundaries) |
| Native packages | Implemented with separate API/agent environments | [Native deployment](../deployment.md#native-installation) |
| Frontend phases 0–14 | Implemented, including identity, administration, portal, import, and shared profiles | [Frontend](../../frontend/README.md), [user guide](../user-guide.md) |
| Rivet rename | Implemented; explicit existing-installation migration required | [Rename](rivet-rename.md) |

## Remaining work

The next release must build and verify the renamed artifacts, finish the
vulnerability review, and verify SBOM/provenance/signatures with the hosted
publication workflow. These were deferred release checks, not completed
security acceptance. Their requirements are in [release readiness](../builds.md#release-verification).

Manual off-host/VM-loss recovery, production RPO/RTO, nonempty access-grant
restore, real Entra sign-in, external UDP ingress, host/Docker restart, and
environment-specific cutover remain deployment-owned. A prior same-host
recovery drill does not close those requirements. No automated backup
scheduler or failover controller is supplied.

## Evidence boundary

Local unit, API, browser, packaging, and static checks support the current
implementation. Historical live checks covered native services, isolated
VPN/Compose behavior, actual host/bridge topology, migration with unchanged
clients, and coordinated same-host recovery. They apply to the artifacts
tested at the time. Reverify newly built Rivet images and any changed platform.

The complete earlier plan and completion log remain available with
`git show 8f506b9:docs/container-architecture-upgrade-plan.md`. Operational
guides now state current behavior and link to executable sources instead of
repeating intermediate phase plans, obsolete test counts, or private-host
procedures.
