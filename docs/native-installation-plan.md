# Native Python installation plan

This plan tracks support for a future non-container Linux release. The native
rehearsal used a frozen private copy of state on an approved test host; the
prior Compose service was restored after native cleanup.

## Package boundary

- Publish one versioned `sciaiot-rivet` core wheel. Its base dependencies cover the VPN
  agent, event hook, shared protocol and migration CLI. `sciaiot-rivet[api]` adds the
  FastAPI service, SQLModel, Uvicorn and required Entra authentication. Optional
  storage and database extras compose with `api`. Two separate virtual
  environments install the same exact core version. `sciaiot-rivet-agent`
  is a metapackage pinned to that version without the API extra.
- The `rivet` command makes a missing `api` extra fail with an actionable
  message. Application code lives only in the core distribution, preventing
  file overlap between API and agent installations.
- Require CPython 3.14 or newer. Include the YAML, legacy hook scripts and
  other runtime package resources in the built wheel. The UI is a separate
  static artifact and is served by Nginx, not the Python wheel.

## Native runtime boundary

- Run the API as a dedicated unprivileged account with `RIVET_VPN_BACKEND=agent`.
  Run the agent as a separate account with only its reviewed Linux capabilities
  and private VPN state. Keep application code and both environments root-owned.
- Give the API only its database/archive/profile state and read access to the
  protected agent control socket. Keep PKI, CCD, journal, management and event
  sockets outside API access. Use fixed numeric peer identities and fail closed
  when the deployment settings are incomplete. Keep `api.env` root:root mode
  0600 so the agent's control-group membership cannot read API credentials;
  systemd loads the file before dropping the API identity.
- Install a reviewed OpenVPN 2.6 server configuration, Easy-RSA 3.1.7,
  iproute2 and `iptables-nft`. Configure the installed event hook using its
  absolute agent virtual-environment path. Provision the owned projection,
  durable journal, socket parents and management permissions before enabling
  mutation families. Start with empty mutations; allocate the route protocol
  and review firewall forwarding before admitting VPN traffic.
- Keep Nginx on the same-origin `/api` boundary. Build the current frontend
  once with runtime Entra configuration, then install immutable static files
  and render validated public settings at service start.

## Work status

- [x] Inspect current package, service, container boundary and tests.
- [x] Implement package dependencies, entry point startup validation and
  native service templates.
- [x] Add focused tests, including clean built-wheel installs and failure
  paths; run complete quality gates.
- [x] Publish a runnable native installation guide and update current links.
- [x] Prepare an opt-in native host rehearsal with explicit stage, start,
  verify, canary mutation and cleanup commands. It requires test-owned paths
  and refuses active native services or path collisions before staging.
- [x] Verify OpenVPN, agent, API, Nginx, issue/assign/connect/revoke and cleanup
  on the approved host; restore the prior Compose service.

## Verification

These results predate the Rivet rename. They establish the original native
deployment behavior, not verification of newly named wheels or images. See
[the rename guide](rivet-rename.md) for the current package boundary and
upgrade requirements.

- Focused native/deployment suite: 45 passed. The complete local suite
  passed 961 tests at 90% total coverage; new application modules: native API
  86%, firewall 84%, asset exporter 92%.
- Isolated source distribution to wheel build and separate clean agent/API
  virtual-environment installs passed `pip check`, isolated imports,
  executable and asset checks. The base agent environment did not install
  FastAPI, SQLModel, Uvicorn or `python-jose`. The installed API answered an
  unauthenticated `/me` request with the expected HTTP 401 and temporary
  SQLite state.
- Repository-wide `ruff format --check .` and `ruff check .` pass after
  source/test consolidation. `mypy .` passes 167 files; configuration excludes
  generated `build/` output while retaining the existing artifacts. Host-only
  deployment tools retain their documented Python 3.12 syntax; application
  code requires Python 3.14. API tests pass in both normal and reverse order
  using disposable per-test databases.
- The full coverage run emitted 29 SQLite `ResourceWarning`s. Isolated API
  and identity runs did not reproduce them; their allocation source remains
  unresolved. No warnings were suppressed.
- `CI=true npm run build:runtime` passed from `frontend/` with the
  deployment-neutral browser bundle and runtime `/api` configuration.
- The local rehearsal helper in `tests/integration/native_host_rehearsal.py`
  passed 10 focused tests, including quoted M0 OpenVPN configuration and
  staging under `umask 077`; scoped Ruff format/check and mypy passed.
- On the approved test host, native OpenVPN, agent, API and Nginx started with
  the expected process IDs, capabilities, socket modes and scoped firewall.
  Direct/proxied unauthenticated API requests returned 401; the UI and
  no-store runtime configuration were served. A test-owned client was issued,
  assigned and connected over a real tunnel, reached its assigned gateway,
  then was unassigned and revoked. The CRL contains its revoked serial.
  After the previous session expired, a fresh 20-second connection attempt
  created no TUN interface or agent session; CRL inspection confirmed the
  serial was revoked. These mutations used the real unprivileged API OS
  identity and typed agent socket, while HTTP authentication was checked with
  denial responses rather than a live Entra token. Native services and
  test-owned state were removed; the original paths were restored, and
  the prior Compose startup service returned active with all four services healthy.
  The unchanged original client credentials and imported CCD reconnected,
  appeared in the agent session list and passed gateway traffic. The agent
  could not read the root-only API env file.
- The final wheel was built and installed into fresh separate agent/API
  environments. Package exports, entry points, imports and `pip check`
  passed; the agent base environment did not include API dependencies.

The approved host rehearsal validates the package, systemd split, real VPN
lifecycle and rollback path. A production environment still needs its own
Entra token, TLS gateway, firewall ingress, PKI and recovery verification.
