# First-party container images

Build all four images from the reviewed source revision and publish them to
your chosen registry. Record the resulting immutable digests for deployment;
the private images used for earlier verification are not release artifacts.
The [verification evidence](container-image-verification.md) records completed
runtime, VPN, migration and recovery checks. Those results apply to the tested
artifacts and do not replace checks of a new release.

Release verification remains deferred: refresh scans and finish the
[vulnerability review](container-vulnerability-review.md), then generate and
verify provenance and signatures with the GHCR release. See the
[deployment reference](container-deployment.md) for runtime requirements.

Use the repository root as the build context. Dockerfiles live in
`deploy/openvpn`, `deploy/agent`, `deploy/api`, and `deploy/nginx`. Compose build
and runtime manifests are separate: `deploy/compose.build.yml` builds tagged
images, while `deploy/compose.yml` consumes operator-recorded immutable image
digests. Follow [container deployment](container-deployment.md) for mounts and
configuration.

For provider-independent local and GitHub Actions builds, follow
[portable container builds](container-builds.md). GHCR is the workflow default;
other OCI registries are configurable. Azure builds below are an optional
provider-specific example, not a project requirement.

## Build locally and push to your registry

Install Docker with Buildx and Compose in your own build environment. The
validated platform is x86_64: use `OVPNCP_PLATFORM=linux/amd64` even on Apple
Silicon. Docker Desktop can cross-build using emulation; a native amd64
Buildx worker is faster. This does not require installing Docker inside this
coding workspace. Do not run the host-network VPN stack on your Mac.

Copy `deploy/container.env.example` to a protected local file outside the
repository build context, then set the registry, image tag and platform.
No Entra settings are needed to build any image. The UI image uses the same
artifact across environments: its three public `OVPNCP_UI_ENTRA_*` settings
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
for each of the four tags. Set `OVPNCP_OPENVPN_IMAGE`, `OVPNCP_AGENT_IMAGE`,
`OVPNCP_API_IMAGE`, and `OVPNCP_WEB_IMAGE` to complete `registry/repository@sha256:…`
references in the deployment environment. Supply those references and build
logs for verification on the selected target before migration.

## Build sequentially on Azure

From the repository root, with Azure CLI authenticated to the subscription
containing your registry, these commands build remotely and push each result.
No local Docker daemon or Entra build arguments are needed.

```bash
set -e
: "${OVPNCP_ACR_NAME:?Set OVPNCP_ACR_NAME to your Azure registry resource name}"
TAG="build-$(date -u +%Y%m%d%H%M%S)"
az acr build --registry "$OVPNCP_ACR_NAME" --platform linux/amd64 \
  --image "ovpncp-openvpn:${TAG}" --file deploy/openvpn/Dockerfile .
az acr build --registry "$OVPNCP_ACR_NAME" --platform linux/amd64 \
  --image "ovpncp-agent:${TAG}" --file deploy/agent/Dockerfile .
az acr build --registry "$OVPNCP_ACR_NAME" --platform linux/amd64 \
  --image "ovpncp-api:${TAG}" --file deploy/api/Dockerfile .
az acr build --registry "$OVPNCP_ACR_NAME" --platform linux/amd64 \
  --image "ovpncp-web:${TAG}" --file deploy/nginx/Dockerfile .
```

These commands are an operator handoff; they have not been executed here.
Capture the four resulting digests and retain build logs. The same inspection,
SBOM/provenance, vulnerability and signature gates apply to Azure builds.

## Runtime contract

Python runtime images remove pip and its ensurepip bootstrap wheel after the
hash-locked dependency install. Package installation belongs to image builds;
runtime containers do not contain pip or its vendored packaging libraries.
The source project continues to use setuptools as its build backend. Removal was verified in the hardening digests recorded in the evidence;
repeat the scan when updating released digests.

The web runtime removes the unused `nginx-module-njs`, `nginx-module-xslt`,
`libxslt1.1` and `libxml2` packages from its pinned base without downloading or
autoremoving other packages. The application uses neither optional module.
Build assertions verify libxml2 is absent and nginx/curl still execute. This
removes unused vulnerable package contents; it does not approve a vulnerability
exception. The hardening web digest passed HTTP checks and a rescan; repeat
these checks for future image updates.

| Image | Identity | Listener / entry point |
| --- | --- | --- |
| OpenVPN | startup 0:65532, daemon 65530:65532 | projected server.conf; UDP configured by operator |
| Agent | startup 0:65532, daemon 65532:65532, control group 65531 | private `/run/ovpn-agent/agent.sock` only |
| API | 65531:65531 | private TCP 8000, one worker |
| Nginx/UI | 101:101 | private HTTP 8080, upstream `api:8000` |

The agent entry point uses isolated Python while root, then drops all root
UID/GID identities and retains only ambient `NET_ADMIN` for Python and its
network-command children. It fails closed on any privilege transition failure.
The image and Compose bootstrap require `NET_ADMIN`, `SETUID` and `SETGID`;
the daemon retains only `NET_ADMIN`. Keep `no-new-privileges` enabled.

OpenVPN and the agent contain the named `ovpn-openvpn`, `ovpn-agent`,
`ovpn-runtime`, and `ovpn-control` identities used by the management peer checks.
OpenVPN's operator-reviewed configuration must drop to `ovpn-openvpn` /
`ovpn-runtime`, stay in the foreground, and write its PID to
`/run/openvpn/openvpn.pid`. Its entry point requires runtime and pool directories
owned 65530:65532 with mode 02770 and precreated status/pool files with mode 0660.
It never repairs permissions or initializes PKI. `/usr/local/bin/ovpncp-vpn-event`
provides the reviewed event hook; its socket arguments remain configuration-owned.

The API accepts `SQLALCHEMY_DATABASE_URI_FILE` and
`AZURE_STORAGE_CONNECTION_STRING_FILE` as direct files beneath `/run/secrets`.
Files must be regular, not symlinks/hardlinks, at most 16 KiB, owned by UID 65531,
and mode 0400 or 0600. Grant its UID read access on the host. Conflicting
inline and file values fail startup. The image contains the existing Entra and
Azure storage dependencies. The reference uses SQLite; optional MySQL/Postgres
drivers need a separately reviewed lock and image variant before use.

`OVPNCP_PROXY_IP` must be one explicit IPv4 address matching Nginx. It is the
only trusted forwarded-header source. API startup requires agent mode and
complete Entra settings. Logging uses stderr/stdout without request access logs
or mutable log files. Run the supplied read-only roots, tmpfs, capability,
resource-limit and mount settings from Compose.

Nginx startup requires `OVPNCP_UI_ENTRA_TENANT_ID` and
`OVPNCP_UI_ENTRA_CLIENT_ID` as UUIDs, plus `OVPNCP_UI_ENTRA_API_SCOPE` as a
concrete `api://host/scope` or `https://host/scope` value (maximum 2048 ASCII
characters; host letters/digits/dots/hyphens and path letters/digits plus
`._~/-`). These settings are public browser configuration, never secrets.
Only these three fields are emitted into `/tmp/ovpncp-runtime-config.js` on the
container's tmpfs. Nginx serves it as `/runtime-config.js` with `no-store`,
before the application initializes. Missing/invalid values stop startup;
missing/invalid browser configuration blocks authentication and never enables
auth bypass. Changing these settings requires recreating the web container,
not rebuilding its image. The legacy static frontend production build and local
Vite development configuration retain their existing environment-file workflow.

Health checks deliberately have distinct meanings: OpenVPN checks daemon and
management-socket liveness, API checks an unauthenticated HTTP denial, and Nginx
checks `/healthz`. Agent health executes bounded management/configuration/TUN/
firewall readiness observations. They do not replace an external authenticated
API/VPN canary or prove host capability confinement. No API health-auth bypass
is introduced.

## Pinned inputs and release evidence

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

Before an image is approved for remote use, the operator must:

1. Retain the source revision, four immutable digests, build logs, base/source
   pins, registry SBOMs and provenance. Review what the attestations contain.
2. Scan every final digest with an approved vulnerability scanner (for example
   `trivy image --exit-code 1 --severity HIGH,CRITICAL IMAGE@sha256:…`). Resolve
   findings or record explicit reviewed exceptions. The initial scan and
   prepared remediation are recorded in [image verification](container-image-verification.md).
3. Sign each digest with the organization's approved Cosign identity/key and
   independently verify signatures against that exact trusted identity/key.
   Signing keys and registry publisher credentials stay outside containers.
4. Inspect final layers for credentials, unexpected tools and dependency drift;
   verify numeric identities and architecture. Use a separate deployment pull
   identity. Validate the attestation subject digest against the deployed image.
5. Rehearse the exact Compose grants, agent readiness, issuance/renewal/revocation,
   event hooks, archive flow, API isolation, backup/restore and external VPN
   traffic in a disposable remote environment before migration approval.

These are pending release gates, not claims that pinned inputs alone produce
bit-for-bit identical images or establish safe runtime privileges.
