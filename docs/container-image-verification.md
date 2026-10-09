# Container image verification evidence

All dated evidence below predates the Rivet rename. It applies to the
original artifacts, not newly built Rivet images. Current source paths in
examples use the new namespace; rebuild and reverify before release.

These historical records describe verification on an operator-provisioned
Linux host using immutable image digests. Host names, registry endpoints and
private evidence locations are managed outside this repository. Each dated
entry refers to its own retained evidence; these artifacts are not deployment
defaults. See the [architecture plan](container-architecture-upgrade-plan.md)
for current phase status.

## Image scan on 2026-09-23

Trivy 0.74.0 scanned private Docker exports with vulnerability and secret
scanners, retaining the full package inventory and generating CycloneDX SBOMs.
The official Linux AMD64 release archive was checked against its published
SHA-256: `2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a`.
The vulnerability database timestamp was `2026-09-23T01:09:35Z`. The scanner
ran unprivileged from a private directory, without mounting the Docker socket
into a scanner container. Disposable image archives were removed after scans.

| Image | Digest | Critical | High | Secret findings |
| --- | --- | ---: | ---: | ---: |
| Agent | `sha256:2c9c0aaf0fc9637f8d509879ec6abe69e1f43c47025e9544acb43d1d5e450c4d` | 0 | 46 | 0 |
| API | `sha256:5e9fc7086070ff032c16694622ffd02d4f2ed91362dd1b7f5a048a5159410f3b` | 0 | 47 | 0 |
| OpenVPN | `sha256:d8b900e3891dbe5d7d77b8765a266b0f8b3c6f81a4ec4ba72775cfb839a100d1` | 0 | 46 | 0 |
| Web | `sha256:c0e580ca2a81c3b1b35318981481f39ed9475ea2372ccafa88dde9b46016f4c9` | 1 | 63 | 0 |

Counts are scanner package findings, not distinct CVEs or demonstrated
exploitable application paths. Zero secret findings is not proof that every
layer is credential-free. Reports and SBOMs are private files under
the private verification directory; each component has
`<component>-scan.json`, `<component>-sbom.cdx.json` and
`<component>-summary.json`. These post-build SBOMs do not establish builder
provenance, signatures or full identification of source-built binaries.

## Prepared remediation and limitations

The Python image findings include `msgpack` 1.1.2
(`GHSA-6v7p-g79w-8964`) and `setuptools` 70.3.0 (`CVE-2025-47273` and
`CVE-2026-59890`). Actual image inspection found no top-level installation of
either library: these are pip vendored payloads, with another bundled pip
wheel under ensurepip. The runtime does not install packages. Dockerfiles now
remove pip and ensurepip after installing/copying application dependencies,
with build-time assertions. Application locks and the setuptools build backend
remain unchanged. Vendored copies require an applicability review: pip retains
only pkg_resources from setuptools, not the full upstream implementation.
See [pip's vendoring policy](https://pip.pypa.io/en/stable/development/vendoring-policy/).

The web critical finding is `CVE-2026-6653` in libxml2. The pinned trixie
package is affected, with no fixed trixie version reported by the
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-6653).
Nginx's linked-library inspection showed no XML/XSLT dependency; the deployed
configuration loads no optional modules. The package-manager simulation
confirmed that removing libxml2 removes only libxslt1.1 and the unused
nginx-module-njs/nginx-module-xslt packages alongside it. The Dockerfile now
purges this exact four-package set without downloads or autoremove, checks
package state and actual library absence, then checks nginx and curl.
Disposable probes confirmed absent libxml2 files. The exact final guarded
Dockerfile instruction then passed, followed by HTTP health, SPA and runtime
configuration checks as UID 101. The exact Python cleanup instructions also
passed with application imports in all three Python images. Cached image
digests were unchanged; these were temporary writable-container experiments.

The subsequent hardening rebuild and rescan below establish the new package
inventory; the preceding experiments describe the earlier image set. These changes do not resolve or accept the remaining Debian or
Python findings. Applicability and any exceptions require recorded review and
expiry as specified by Phase 5. No blanket suppression or exception was added.
Registry build logs/provenance and organizational signing/verification remain
outstanding and were deferred by the operator on 2026-09-24; functional
verification and portable build work continue. Full container integration and migration compatibility remain
separate gates.

## Disposable VPN rehearsal

The [container rehearsal](../tests/integration/README-container.md) generates
its own CA and two clients, with three attested and pinned network namespaces.
It uses no host-network containers, published ports, Docker bridges or
production state mounts. The agent and OpenVPN use their actual image
entrypoints; the API-image probe uses the deployed UID and socket transport.

The first three attempts established UDP/CCD/session behavior and exposed a
fixture gateway issue: an ICMP host redirect made one-packet ping exit before
counting the real echo reply. Packet-type-only diagnostics confirmed both
reply and redirect. The harness now disables redirect emission for all/default
interfaces exclusively inside its pinned server namespace before TUN creation.
The strict traffic assertions remain unchanged.

Attempt 4 passed: two real UDP clients, actual tunnel addresses matching CCD,
management sessions, default deny, managed allow, denial after removing access
(despite a broad established-flow accept behind the TUN anchors), same-ID
mutation replay, and data-plane survival across agent SIGKILL/restart.
It reports `full_phase6: false`: HTTP/RBAC and web integration, credential
issuance/revocation/CRL enforcement, reconnect/reboot, crash-during-mutation,
backup/restore and actual production Compose topology still need verification.

All attempts cleaned up their synthetic state and containers. Normalized host
links, addresses, IPv4/IPv6 routes and policy rules, IPv4/IPv6 firewall, the
existing VPN PID/service state and server configuration were unchanged.
Private attempt evidence is retained under
the private verification directory; `attempt4-result.json` and
`attempt4-invariance.json` record the passing run. No production import or
cutover occurred.

Final local checks on 2026-09-24 passed:

- `ruff format --check .` (157 files).
- `ruff check .`.
- `mypy --no-incremental --exclude '^build/' .` (138 source files).
- `pytest --cov=src/sciaiot/rivet --cov=deploy/containers
  --cov-report=term-missing` (776 passed, 90% combined coverage).
- `git diff --check`.


## Hardening rebuild and scan on 2026-09-24

All four images were rebuilt and pulled with tag `phase5-hardening-20260924`.
The cached AMD64 digests, scan counts and post-build CycloneDX SBOMs are:

| Image | Digest | Critical | High | Secret findings |
| --- | --- | ---: | ---: | ---: |
| Agent | `sha256:fa47a166ffe3e37a5957e16c4b894a6b7da4a1b723ae6124e1d74049a598cae1` | 0 | 44 | 0 |
| API | `sha256:147c9e43e45baa15ee8da946ee7a68df38c7edce5f9f4bbac7e2bcd478cca20f` | 0 | 45 | 0 |
| OpenVPN | `sha256:5027eba02fbb4872c1b9c1ff8f084d41431dd671870ee7f48ba03877683253fa` | 0 | 44 | 0 |
| Web | `sha256:471fe06e616974c4491d604e667b86b66f753e28ef20d423faf9a2e6f47889a4` | 0 | 59 | 0 |

Trivy 0.74.0 used database timestamp `2026-09-23T20:20:57.734988316Z`.
Reports/SBOMs are retained beneath
the private verification directory.
The removed pip/ensurepip vendored payloads and web XML/XSLT packages are absent.
No fixed versions were listed for the remaining high findings in that scan.
These counts are historical evidence, not a continuously updated scan.
The [applicability review](container-vulnerability-review.md) accounts for all
20 distinct advisories across 192 high-finding rows, without granting waivers.

The baseline VPN rehearsal passed again on these digests; evidence is
`hardening-baseline-result.json` and `hardening-baseline-invariance.json` in the
rehearsal directory above. Web checks passed for rejected missing configuration,
HTTP health, SPA serving and runtime configuration/no-store behavior. These
checks did not modify the host VPN or start the production Compose stack.

## Extended rehearsal on 2026-09-27

The current three-client harness passed on the hardening digests above:

- Actual UDP connectivity, CCD addresses, allow/deny traffic and same-ID replay.
- VPN survival across agent SIGKILL/restart and real HTTP API/probe outage.
- Unauthenticated HTTP requests rejected by the actual API entrypoint.
- Agent-issued credentials and verified archive, connection and reconnection.
- Signed CRL projection, revoked archive denial, session disconnect and repeated
  revoked-client handshake rejection while unaffected peers retained traffic.
- Client deletion and removal of its authoritative private key.

Cleanup passed and all eleven host invariance comparisons matched: links,
addresses, IPv4/IPv6 routes, rules and firewall, VPN PID, active state and server
configuration. Private evidence is `lifecycle-20260927-result.json` and
`lifecycle-20260927-invariance.json` under
the private verification directory.

The result deliberately remains `full_phase6: false`. Valid-token HTTP/RBAC,
web edge integration, renewal, crash-during-mutation, reboot/restore, full
production Compose topology and migration compatibility still need proof.
Provenance/signing handoff is deferred at the operator's request. No production
cutover or source PKI migration occurred.

Exact-image read-only applicability probes are retained in
`hardening-applicability-20260927.json`.
They confirm the API's cryptography backend and no Expat/TIFF/X11/XML/ACL links
from nginx or curl. Standard systemd-homed/tiffcrop paths were absent and no
Archive/Tar.pm was found under `/usr/share`, `/usr/lib` or `/usr/local/lib`.
This narrows reviewed paths; it does not establish absence of every consumer
or accept remaining findings.


Local checks after the portability and harness changes on 2026-09-27 passed:

- `ruff format --check .` (160 files) and `ruff check .`.
- `mypy --no-incremental --exclude '^build/' .` (139 source files).
- `pytest --cov=src/sciaiot/rivet --cov-report=term-missing`
  (799 passed, 90% application coverage).
- Official checksum-verified actionlint v1.7.7 with `-shellcheck=` against
  `.github/workflows/containers.yml` (passed; ShellCheck was not run).

Plain `mypy .` reports duplicate modules in existing generated `build/lib`;
that output was preserved and excluded in the successful source check.
No hosted GitHub Actions build, registry publication or production deployment
was performed. Per the operator's 2026-09-27 decision, the first hosted run
and artifact verification are deferred until all architecture phases are
finished. They remain unverified post-phase follow-up, not a P5 closure or
phase progression gate. The operator subsequently deferred remaining image
vulnerability review until before the GHCR release and grouped provenance and
signing verification with that release. P5 implementation is complete with
those release checks deferred; none is recorded as passed by this decision.


## Phase 6 Compose integration on 2026-09-29

The isolated Compose rehearsal passed with the hardening agent, OpenVPN and
web digests listed above. It started and rolled back to the prior API digest
`sha256:5e9fc7086070ff032c16694622ffd02d4f2ed91362dd1b7f5a048a5159410f3b`,
and upgraded to the hardening API digest
`sha256:147c9e43e45baa15ee8da946ee7a68df38c7edce5f9f4bbac7e2bcd478cca20f`.
All images came from the existing local cache; no rebuild, pull or release
approval is implied by this functional test.

The first attempt retained private evidence under
the private verification directory. Compose services became healthy
and the signed HTTP fixture reported `passed`, but a Docker image inspection
timed out and automatic cleanup was incomplete. Resource diagnostics showed
about 90 MiB available on a single-CPU, approximately 0.8 GiB host with no swap;
this suggests pressure but does not establish the timeout cause. The retained
`manual-cleanup-20260928.json` and `manual-cleanup-invariance.json` confirm
removal of all 20 owned containers and synthetic state, and unchanged host
VPN/network state.

After reducing helper overhead, the successful run retained evidence under
the private verification directory:

- `compose-20260928-result.json`: exit success, all functional checks passed,
  cleanup passed and a distinct upgrade image confirmed.
- `compose-20260928-invariance.json`: all eleven host comparisons matched.
- Matching `-before.json` and `-after.json`: private host-state fingerprints.

The evidence filenames retain the wrapper's earlier date label. This resumed
verification is recorded here on 2026-09-29. A subsequent container inventory
found no rehearsal containers remaining.

Passing checks include readiness-gated startup of all four services; Nginx
health and runtime configuration; real API verification of synthetic signed
JWTs and role restrictions; identity persistence across API recreation;
three real UDP clients; CCD addresses; allowed/denied traffic; mutation replay;
agent loss/restart; credential issuance/archive/reconnect/revoke/delete; and
signed CRL projection with revoked handshake rejection. API/web stop/restart,
upgrade and rollback preserved VPN traffic and OpenVPN/agent IDs and PIDs.

The tampered-signature probe accepts either 401 or 500 with a problem-response
content type. Its result does not retain which status occurred or assert
response-body redaction for that case; it does not establish that every
invalid token returns 401. No application authentication bypass was introduced.

The runner substitutes owned private namespaces for the reference host and
bridge networks. Consequently `production_network_topology: false` and
`full_phase6: false` remain explicit. At that point, the documented actual
host/bridge deploy/verify/upgrade/rollback workflow still needed verification;
the operator subsequently authorized the existing-host rehearsal below. Source migration, reboot/restore and release evidence are
not established by this run. The production VPN remained active and unchanged.

Local checks passed after these harness changes:

- `ruff format --check .`: 163 files.
- `ruff check .`.
- `mypy --no-incremental --exclude '^build/' .`: 142 source files.
- `pytest --cov=src/sciaiot/rivet --cov=deploy/containers
  --cov-report=term-missing`: 812 passed, 90% combined coverage.
- Focused container/harness tests: 45 passed.


## Actual-topology maintenance attempt on 2026-09-29

The operator authorized stopping the existing application and VPN on
the approved test host to test fresh deployment state with the actual host/bridge
network layout. This is an existing provisioned host, not an OS installation.

The first attempt retained root-private evidence at
the private verification directory. It stopped both source services, created an
encrypted backup, and verified all 102 captured entries against frozen source
content and filesystem metadata. No source state was imported into containers.
Preflight then stopped on an unhandled null `IPAM.Config` in Docker's built-in
network inventory, before starting the Compose deployment.

The runner reported cleanup passed. Source fingerprints were unchanged and
all eleven stopped-host comparisons matched (links, addresses, IPv4/IPv6
routes, rules and firewall, forwarding and both redirect settings). A second
comparison passed before the maintenance guard restarted the source services;
both `rivet.service` and `openvpn@server.service` were active afterward.
`maintenance-status.json`, `host-compose-result.json`, source-code hashes and
private backup/inventory files retain the evidence. This failed preflight is
not recorded as actual-topology success.


The second actual-topology attempt used the corrected built-in-network
preflight and retained evidence under the private verification directory.
It verified another encrypted 102-entry source backup, started the real
host/bridge Compose services, passed signed HTTP checks through the published
loopback web port, and connected the synthetic UDP clients. It failed at the
first access mutation; the recorded typed-probe error was not yet detailed
enough to distinguish its error code. Subsequent read-only inspection found
that the agent's foreign-policy guard rejects both broad Docker FORWARD jumps
(`DOCKER-USER` and `DOCKER-FORWARD`). Changing the mutation probe's retry behavior
alone does not resolve this integration conflict.

Container/network/test-rule cleanup passed, source fingerprints matched, and
ten of eleven stopped-host comparisons matched. The restoration guard paused
because Docker initialized an empty IPv4 `raw` table. Manual inspection proved
that this table had no rules and only ACCEPT built-in policies; omitting that
new empty table reproduced the exact original firewall hash. Existing rules
and all other network/sysctl state matched. `manual-restoration.json` records
that proof, zero remaining test containers and successful restoration of both
source services. No foreign firewall rule was removed or relaxed.

At the end of this attempt, actual-topology access mutation and
upgrade/rollback remained unverified. The corrected image and successful
repeat run below supersede that incomplete status.


## Actual-topology verification passed on 2026-09-30

The normal `deploy/agent/Dockerfile` built successfully on the test host from
reviewed source with its pinned base/dependencies. The local-only immutable
reference is
`sha256:ed2acbab21303bc49afbac419cdc1f7dcb67e4cb01336124c3ed611a87f6d82f`.
Root-private build context hashes, image ID and logs are retained under
the private image-build evidence directory. No registry publication or release
signing/provenance approval is implied. OpenVPN and web used their existing
hardening digests; API started at the prior digest listed above, upgraded to
the distinct hardening digest, then rolled back. Web was recreated and its
runtime configuration changed and restored with those bundles.

The maintenance evidence is retained under
the private verification directory:

- `maintenance-status.json` and `maintenance-output.json`: overall passed,
  runner exit 0, verified encrypted backup of all 102 captured source entries,
  unchanged source fingerprints and both original services restored active.
- `host-compose-result.json`: actual host/bridge topology, readiness, signed
  JWT/RBAC through Nginx, API identity persistence, synthetic allowed/denied
  flows, API/web upgrade/rollback, VPN traffic/process survival and cleanup all
  passed. Source state was not imported.
- `host-stopped-before.json`, `host-stopped-after.json` and
  `host-stopped-invariance.json`: all eleven network/firewall/sysctl comparisons
  passed. A fresh comparison before source restart also matched. Private raw
  firewall snapshots support the fingerprints.
- Source-code hashes, private source inventory and verified encrypted backup
  remain on the host for traceability; no credentials are copied into this
  document.

The corrected agent requires both input and output TUN selectors on owned
ACCEPT rules and conservatively proves reachable foreign policy cannot deny
those grants. No Docker chain-name exception or foreign-policy modification
was used. The HTTP fixture also checks that neither original nor tampered JWT
appears in the tampered-signature response; that case still accepts 401 or 500
with a problem response, so it does not prove a uniform 401 error contract.

Local checks for the final implementation passed:

- `ruff format --check .`: 165 files; `ruff check .` passed.
- `mypy --exclude '^build/' .`: 144 source files. Plain `mypy .` encounters
  duplicate `sciaiot` packages in generated `build/lib`.
- `pytest --cov=src/sciaiot/rivet --cov=deploy/containers
  --cov-report=term-missing`: 848 passed, 90% combined coverage.
- Focused firewall/container checks: 120 passed; `git diff --check` passed.

The combined isolated credential/lifecycle proof and actual reference-topology
proof complete Phase 6 under the operator-approved scope: an existing
provisioned Linux host with fresh deployment state. Each runner retains
`full_phase6: false` because neither alone covers the entire phase. This does
not establish pristine-OS provisioning, source migration, reboot recovery or
Phase 7 restore/cutover. P5 vulnerability review and hosted release
provenance/signing checks remain deferred under the agreed GHCR schedule.
