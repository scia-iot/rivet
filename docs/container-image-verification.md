# Container image verification evidence

Remote target: `fdsadmin@sciaiot-openvpn`. Images are in
`faureciaiot-b8c8fwavbhdudve2.azurecr.io`. Verification uses immutable digests;
no production cutover has occurred. See the
[architecture plan](container-architecture-upgrade-plan.md) for phase status.

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
`/home/fdsadmin/.ovpncp-image-evidence-vcfnq8y6`; each component has
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
`/home/fdsadmin/.ovpncp-p6-container-jmpe6950`; `attempt4-result.json` and
`attempt4-invariance.json` record the passing run. No production import or
cutover occurred.

Final local checks on 2026-09-24 passed:

- `ruff format --check .` (157 files).
- `ruff check .`.
- `mypy --no-incremental --exclude '^build/' .` (138 source files).
- `pytest --cov=src/sciaiot/ovpncp --cov=deploy/containers
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
`/home/fdsadmin/.ovpncp-image-evidence-vcfnq8y6/hardening-20260924-ujm0njq3`.
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
`/home/fdsadmin/.ovpncp-p6-container-jmpe6950`.

The result deliberately remains `full_phase6: false`. Valid-token HTTP/RBAC,
web edge integration, renewal, crash-during-mutation, reboot/restore, full
production Compose topology and migration compatibility still need proof.
Provenance/signing handoff is deferred at the operator's request. No production
cutover or source PKI migration occurred.

Exact-image read-only applicability probes are retained in
`/home/fdsadmin/.ovpncp-image-evidence-vcfnq8y6/hardening-applicability-20260927.json`.
They confirm the API's cryptography backend and no Expat/TIFF/X11/XML/ACL links
from nginx or curl. Standard systemd-homed/tiffcrop paths were absent and no
Archive/Tar.pm was found under `/usr/share`, `/usr/lib` or `/usr/local/lib`.
This narrows reviewed paths; it does not establish absence of every consumer
or accept remaining findings.


Local checks after the portability and harness changes on 2026-09-27 passed:

- `ruff format --check .` (160 files) and `ruff check .`.
- `mypy --no-incremental --exclude '^build/' .` (139 source files).
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`
  (799 passed, 90% application coverage).
- Official checksum-verified actionlint v1.7.7 with `-shellcheck=` against
  `.github/workflows/containers.yml` (passed; ShellCheck was not run).

Plain `mypy .` reports duplicate modules in existing generated `build/lib`;
that output was preserved and excluded in the successful source check.
No hosted GitHub Actions build, registry publication or production deployment
was performed. The checked-in workflow still needs its first hosted run.
