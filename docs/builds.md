# Builds and releases

Build Python packages, browser assets, and container images from one
reviewed revision. This guide covers local and hosted builds, publishing,
and the checks required before accepting a release. Installation and
environment-specific startup are in [deployment](deployment.md).

- [Build and publish artifacts](#build-and-publish-artifacts)
- [Release verification](#release-verification)

## Build and publish artifacts

Build all four first-party images from one reviewed revision and publish them
to your chosen OCI registry. Record immutable digests for deployment. Python
packages and the UI can also be built independently for native installation.
Runtime requirements are in [container deployment](deployment.md#container-deployment)
and [native deployment](deployment.md#native-installation); pending release approval is in
[release readiness](#release-verification).

### Container inputs and names

Use the repository root as the build context. No Entra account, credential,
or deployment state is required to build any image.

| Image | Dockerfile |
| --- | --- |
| `rivet-openvpn` | `deploy/openvpn/Dockerfile` |
| `rivet-agent` | `deploy/agent/Dockerfile` |
| `rivet-api` | `deploy/api/Dockerfile` |
| `rivet-web` | `deploy/nginx/Dockerfile` |

`deploy/compose.build.yml` builds tags; `deploy/compose.yml` consumes exact
deployment digests. Set `RIVET_REGISTRY` to a registry host and optional
namespace, such as `ghcr.io/my-organization`, `docker.io/my-account`, or
`registry.example.com/team`. It is a naming prefix, not a URL.
`RIVET_IMAGE_TAG` defaults to `dev`.

Only the Linux AMD64 reference has prior runtime validation. Cross-platform
base manifests and wheel locks do not establish ARM64 deployment support;
reverify any other platform. Current renamed images require fresh builds and
runtime checks even on AMD64.

### Build locally and publish

Install Docker with Buildx and Compose in your own build environment. The
validated platform is x86_64: use `RIVET_PLATFORM=linux/amd64` even on Apple
Silicon. Docker Desktop can cross-build using emulation; a native amd64
Buildx worker is faster. Runtime verification requires a compatible Linux host, not a Docker Desktop
VPN deployment.

Copy `deploy/container.env.example` to a protected local file outside the
repository build context, then set the registry, image tag and platform.
No Entra settings are needed to build any image. The UI image uses the same
artifact across environments: its three public `RIVET_UI_ENTRA_*` settings
are supplied only when the container starts. The build fixes authentication
on, requires runtime configuration, and fixes the API URL to `/api`. Local
frontend environment files and process `VITE_*` settings are not embedded by
the container build mode.

From the repository root, after authenticating your own Docker client to your registry:

```sh
docker compose --env-file /absolute/path/container.env \
  -f deploy/compose.build.yml config --quiet
docker compose --env-file /absolute/path/container.env \
  -f deploy/compose.build.yml build --provenance=mode=max --sbom=true
docker compose --env-file /absolute/path/container.env \
  -f deploy/compose.build.yml push
```

Your builder/image store must preserve attestations. If the local Docker
image store cannot retain them, use a Buildx builder with registry export:
load the nonsecret build variables into your shell and run
`docker buildx bake -f deploy/compose.build.yml --push --provenance=mode=max
--sbom=true`. This combined build-and-push is an operator action. Inspect the
registry afterward; a successful build alone does not prove SBOM or provenance
retention. Keep private runtime variables out of build environments and args.

Capture the pushed manifest digests using `docker buildx imagetools inspect`
for each of the four tags. Set `RIVET_OPENVPN_IMAGE`, `RIVET_AGENT_IMAGE`,
`RIVET_API_IMAGE`, and `RIVET_WEB_IMAGE` to complete `registry/repository@sha256:…`
references in the deployment environment. Supply those references and build
logs for verification on the selected target before migration.

### Build sequentially on Azure

From the repository root, with Azure CLI authenticated to the subscription
containing your registry, these commands build remotely and push each result.
No local Docker daemon or Entra build arguments are needed.

```bash
set -e
: "${RIVET_ACR_NAME:?Set RIVET_ACR_NAME to your Azure registry resource name}"
TAG="build-$(date -u +%Y%m%d%H%M%S)"
az acr build --registry "$RIVET_ACR_NAME" --platform linux/amd64 \
  --image "rivet-openvpn:${TAG}" --file deploy/openvpn/Dockerfile .
az acr build --registry "$RIVET_ACR_NAME" --platform linux/amd64 \
  --image "rivet-agent:${TAG}" --file deploy/agent/Dockerfile .
az acr build --registry "$RIVET_ACR_NAME" --platform linux/amd64 \
  --image "rivet-api:${TAG}" --file deploy/api/Dockerfile .
az acr build --registry "$RIVET_ACR_NAME" --platform linux/amd64 \
  --image "rivet-web:${TAG}" --file deploy/nginx/Dockerfile .
```

Capture the four resulting digests and retain build logs. The same inspection,
SBOM/provenance, vulnerability and signature gates apply to Azure builds.


### GitHub Actions

`.github/workflows/containers.yml` runs all four AMD64 builds on pull requests,
pushes, published GitHub releases, and manual dispatch. Ordinary builds have
only `contents: read`, never log into a registry, and never publish.
Checkout does not persist credentials.
All new actions are pinned to immutable commits from the official action
repositories.

Each successful build uploads `container-COMPONENT-RUN_ID` for seven days:

- `image.oci.tar`: an OCI image layout archive for import into compatible tools.
- `metadata.json`: Buildx metadata, including `containerimage.digest`.
- `image.txt`: the intended image tag, including the full checked-out SHA.
- `archive.sha256`: archive checksum, distinct from the image manifest digest.

A pull-request build uses GitHub's merge revision. The OCI archive is a build
artifact; plain `docker load` support depends on the engine's image store.
For example, an installed OCI-aware `skopeo` can import it locally with
`skopeo copy oci-archive:image.oci.tar docker-daemon:rivet-api:review`.
Artifacts consume GitHub storage; large builds may need a higher account quota.

Publishing a GitHub release triggers **Container builds**, alongside the
existing PyPI **Package** workflow. All four images are built from the release's
tagged commit. After every nonpublishing build succeeds, a separate job obtains
package-write permission and rebuilds that revision with two tags:

- `rivet-COMPONENT:0.1.7` for a release tagged `v0.1.7` or `0.1.7`.
- `rivet-COMPONENT:sha-FULL_SHA` for the release commit.

Release tags must use `MAJOR.MINOR.PATCH`, optionally prefixed with `v` and
followed by a prerelease suffix, such as `v0.1.8-rc.1`. Published prereleases
receive the corresponding `0.1.8-rc.1` image tag. Build metadata (`+...`) is not
supported, and the image tag must fit Docker's 128-character limit. Invalid
release tags fail before any image is published. No `latest` tag is assigned.

To publish a version, merge the workflow changes, update the Python package
versions together, and create a GitHub release with a matching version tag
on that commit. The tagged commit must contain this release-enabled workflow;
publishing a release for an older commit uses its older workflow. Pushing a
tag alone does not publish images, and editing an existing release does not
trigger publication. The PyPI and container workflows run independently.

A manual **Container builds** dispatch with `publish=true` on the default
branch remains available and publishes only SHA tags. Manual dispatches on
other branches build but skip publishing. Neither publishing path deploys.

Repository configuration:

| Setting | Default / meaning |
| --- | --- |
| Variable `CONTAINER_REGISTRY` | `ghcr.io`; lowercase host, optionally with port, without scheme or path |
| Variable `CONTAINER_NAMESPACE` | Lowercase repository owner on GHCR; optional for external registries with root repositories (such as ACR); required for Docker Hub account names |
| Secret `CONTAINER_REGISTRY_USERNAME` | Required for external publishing only |
| Secret `CONTAINER_REGISTRY_PASSWORD` | Required for external publishing only; registry-scoped token/password |

GHCR uses `github.actor` and `GITHUB_TOKEN`. External registry login uses only
the two explicit secrets and fails if either is absent; it never falls back to
`GITHUB_TOKEN`. Configure the chosen namespace's registry permissions before
publishing. GHCR packages may also require repository write access to be granted
when the package already exists.

Published builds retain `published-COMPONENT-RUN_ID` metadata and image tags
for 30 days. Use **published** `containerimage.digest` values when preparing
runtime image references. A rebuild can differ from the earlier OCI artifact,
and the four matrix pushes are not atomic: inspect all job results before
selecting a deployment set. Re-running a publication may move its image tags;
immutable deployment digests remain the source of truth.

SBOM attestations are requested for both OCI exports and published builds
(`--sbom=true`); consuming them requires an OCI attestation-aware tool or
registry. SBOM generation alone is not vulnerability scanning. Provenance and
signing handoff are explicitly deferred (`--provenance=false`). Build metadata
is not signed provenance and a successful workflow is not release security
approval. Complete the separate [release checks](#release-verification).
No workflow performs migration or production cutover.


### Pinned inputs


All external image stages use multi-platform SHA-256 manifest pins. Debian
package installation uses the fixed authenticated snapshot
`20260920T000000Z`, including trixie-security; snapshot metadata expiry checking
is disabled, signature checking remains enabled. Refresh pins deliberately
when applying security updates. The build downloads OpenVPN 2.6.19 and Easy-RSA
3.1.7 from their official GitHub release assets and verifies fixed SHA-256
hashes before extraction. Easy-RSA renewal remains explicitly version-gated.

Python runtime closures are in `deploy/locks/api.txt` and `agent.txt`; exact
versions and PyPI wheel hashes support CPython 3.14 on amd64 and arm64. Images
use `--require-hashes --only-binary=:all:` and fail if a compatible wheel is
absent. API images install the runtime dependencies directly and copy the
first-party source, avoiding build-system downloads and development extras.
The frontend uses its package-lock and
`npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps=false`.
TypeScript 5.9.3 satisfies the OpenAPI generator's declared peer requirement;
local, image and CI installs must not bypass peer resolution. Compiler and
Node toolchains stay in build stages. The root `.dockerignore`
uses an allowlist with final credential exclusions: local env files, PKI,
state, Git metadata, node_modules and prior builds are not build inputs.



### Native Python and UI artifacts

Build from a clean checkout/environment so stale `build/`, `dist/`, or
egg-info output cannot enter an artifact. The package version and the agent
metapackage's exact core dependency must move together.

```bash
python -m pip install build
python -m build
python -m build packages/agent --outdir dist
```

This produces wheels and source distributions named `sciaiot_rivet` and
`sciaiot_rivet_agent`. The core wheel contains `sciaiot.rivet`, entry points,
and exportable native templates. The agent wheel contains metadata requiring
the exact core release, without API extras. Neither wheel contains the UI.
The package workflow publishes both distributions on a release event; configure
trusted publishing for both new names before enabling that release.

From `frontend/`, build the portable static UI:

```bash
npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps=false
npm run build:runtime
```

Deploy `frontend/dist` together with runtime public configuration as described
in [native installation](deployment.md#browser-ui-and-https-proxy).
The private npm package name is `@sciaiot/rivet-web`; no npm publication is
required for the browser application.

## Release verification

The architecture, native packaging, portable container definitions, and Rivet
rename are implemented. This does not establish that new packages/images have
been published or approved for a production deployment. The requirements below
remain separate from completed implementation.

### Artifact release

| Requirement | Current status / next action |
| --- | --- |
| Rivet Python distributions | Core and matching agent metapackage build and install locally. Configure trusted publishing for both new PyPI names and publish an exact matching version. |
| Four Rivet container images | Dockerfiles/Compose/CI use the new names. Build all four from one reviewed revision; do not relabel older images as the new implementation. |
| Hosted GitHub/GHCR verification | Workflow exists; first hosted artifact/publication verification was deferred. Run it and inspect the actual published manifest digests. |
| SBOM and provenance | Workflow requests SBOMs. Provenance is currently disabled; implement/collect and independently verify it against each released digest. Metadata alone is not signed provenance. |
| Signatures | Select the trusted signing identity/public key, sign each digest, and verify independently. No signing implementation or approval is implied by the workflow. |
| Vulnerabilities | Refresh scans for exact release digests. Resolve applicable findings or record explicit digest/advisory decisions with owner and expiry; no blanket waiver exists. |
| Runtime regression | Rehearse actual grants, peer identities, forbidden mount access, client lifecycle, traffic policy, events, and recovery using the new artifacts. |

Local tests do not replace container builds or a live VPN rehearsal. Previous
functional evidence predates the Rivet rename and cannot be attributed to
unbuilt renamed images. Cached private test images are not release defaults.

### Vulnerability review still required

The last pre-rename image review retained unresolved package findings; its
scan counts and fixed-version fields are historical, not current assertions.
In particular, review indirect libacl use around writable state and optional
web dependency chains before claiming non-applicability. Distinguish an
installed library from a vulnerable tool/module that may not be present.

For each final digest, retain a current package inventory, scanner/database
version, advisory evidence, loaded consumers, and the configuration/capability
assumptions behind the decision. Read-only roots, `no-new-privileges`, and
absence of an application call narrow exposure; they do not repair a vulnerable
library. Do not remove essential packages or mix distribution releases merely
to reduce duplicated scanner rows.

Python runtime images remove pip/ensurepip after dependency installation;
the web image removes unused XML/XSLT/njs payloads. These build instructions
must be verified in newly produced images, with fresh scans and runtime checks.
No existing code-exclusion analysis grants a formal exception or expiry.

Detailed pre-consolidation evidence remains retrievable from Git:

```bash
git show 8f506b9:docs/container-vulnerability-review.md
git show 8f506b9:docs/container-image-verification.md
```

### Deployment acceptance

The operator owns these checks in the actual deployment environment:

- Real Entra browser login and delegated/app-only permission denial;
  synthetic signed-token tests do not prove tenant configuration.
- Public HTTPS and separate VPN UDP reachability, gateway/host ingress,
  forwarding, NAT when needed, address overlap, and cipher/profile compatibility.
- Safe host reboot and Docker-daemon restart ordering, including the owned
  firewall baseline before admitting VPN traffic.
- Full VM/off-host recovery and key recovery, measured RPO/RTO, and restoration
  of nonempty access grants as well as routes and revocations. See [recovery](data-management.md#backup-and-recovery).
- Capacity, disk limits, performance, alerting, and a maintenance/rollback plan.
  The prior reference sizing and availability targets are not achieved SLAs.

Azure-specific edge/network configuration and production cutover remain
deferred to that environment. High availability is optional future deployment
work; multiple API/VPN writers or replicas are not enabled by this reference.
