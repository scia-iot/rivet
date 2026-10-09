# Portable container builds

The four first-party Dockerfiles build OpenVPN, the VPN agent, the API, and
Nginx/UI independently. Builds need Docker with Buildx, or Docker Compose v2,
and public package/base-image network access. No Azure account or registry is
required. Optional Entra ID and Azure storage integrations remain in the
application; their runtime settings are not build credentials.

Only `linux/amd64` is currently validated. Do not treat a platform override as
proof of ARM64 support. Runtime security, state preparation, and deployment
remain covered by the [deployment reference](container-deployment.md).

## Local builds

Copy `deploy/container.env.example` to the ignored `deploy/container.env`.
`RIVET_REGISTRY` is a registry host plus an optional namespace, for example
`ghcr.io/my-organization`, `docker.io/my-account`, or
`registry.example.com/team`. Root-level repositories also work, such as
`registry.example.com/rivet-api` when
`RIVET_REGISTRY=registry.example.com`. It is an image naming prefix, not a URL. Choose
`RIVET_IMAGE_TAG` for the build.

```bash
docker compose --env-file deploy/container.env \
  -f deploy/compose.build.yml build
```

This builds and tags locally without logging in, publishing, starting services,
or reading deployment state. If publishing is desired, authenticate separately
with the registry's supported login method, then run:

```bash
docker compose --env-file deploy/container.env \
  -f deploy/compose.build.yml push
```

The build Compose file is separate from `deploy/compose.yml`, whose runtime
image variables require operator-selected immutable digest references.

## GitHub Actions

Before the deferred GHCR release, refresh scans and finish the image
vulnerability review, resolving applicable findings or recording explicit
acceptance with expiry. Generate and verify provenance and signatures with
that release, alongside SBOM attestations and the published image digests.
These deferred release checks do not block architecture phase progression;
the current workflow does not yet implement provenance/signing.

The first hosted run and verification of its artifacts are deferred until all
architecture phases are finished, per the operator's 2026-09-27 decision.
The workflow is implemented and locally validated; hosted execution is a
post-phase follow-up and does not block phase progression. No workflow has
been pushed or dispatched as part of this handoff.

`.github/workflows/containers.yml` runs all four AMD64 builds on pull requests,
pushes, and manual dispatch. Ordinary builds have only `contents: read`, never
log into a registry, and never publish. Checkout does not persist credentials.
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

Publishing requires a manual **Container builds** dispatch with `publish=true`
on the repository's default branch. A separate job obtains package-write
permission only after every nonpublishing build succeeds. It rebuilds the same
revision and publishes `rivet-COMPONENT:sha-FULL_SHA`; it does not deploy. A
manual dispatch on any other branch still builds but skips publishing.

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
selecting a deployment set. Re-running a publication may move the SHA tag;
immutable deployment digests remain the source of truth.

SBOM attestations are requested for both OCI exports and published builds
(`--sbom=true`); consuming them requires an OCI attestation-aware tool or
registry. SBOM generation alone is not vulnerability scanning. Provenance and
signing handoff are explicitly deferred (`--provenance=false`). Build metadata is not signed
provenance and a successful workflow is not release security approval. Existing
[image verification](container-image-verification.md) and
[vulnerability review](container-vulnerability-review.md) evidence remain
separate. No workflow performs migration or production cutover.

Action revisions were checked against official repository tags:
[checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2),
[upload-artifact v4.6.2](https://github.com/actions/upload-artifact/releases/tag/v4.6.2),
[setup-buildx v3.11.1](https://github.com/docker/setup-buildx-action/releases/tag/v3.11.1),
and [login v3.5.0](https://github.com/docker/login-action/releases/tag/v3.5.0).
The [Docker OCI exporter documentation](https://docs.docker.com/build/exporters/oci-docker/)
describes the archive format. Action pins do not make the hosted runner,
Buildx/BuildKit defaults, or package mirrors immutable.
