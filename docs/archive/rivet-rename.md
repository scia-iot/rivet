# Archived: ovpncp-to-Rivet rename

> Historical transition guide, archived on 2026-10-09. Applies only to
> installations upgrading from ovpncp. Use the [current documentation](../README.md)
> for new deployments and review these steps against the selected release.

Rivet is the OpenVPN control plane formerly named `ovpncp`. This release
renames the public packages, commands, configuration, and deployment assets.
It does not change the REST endpoints, authentication model, database schema,
or VPN protocol.

## Public names

| Interface | Rivet name |
| --- | --- |
| API installation | `sciaiot-rivet[api]` |
| Agent installation | `sciaiot-rivet-agent` |
| Shared Python implementation | `sciaiot.rivet` |
| API / agent commands | `rivet` / `rivet-agent` |
| Other commands | `rivet-vpn-event`, `rivet-migrate`, `rivet-export-native`, `rivet-native-firewall` |
| Container repositories | `rivet-api`, `rivet-agent`, `rivet-openvpn`, `rivet-web`, under your registry namespace |
| Compose project | `rivet` |
| Project environment variables | `RIVET_*` replaces `OVPNCP_*` |
| Native units | `rivet`, `rivet-agent`, `rivet-openvpn`, `rivet-forward-policy` |
| API state root | `/opt/rivet` |
| Native settings / virtual environments | `/etc/rivet` / `/usr/local/lib/rivet` |
| Static UI root | `/srv/rivet/frontend` |

The agent distribution is a small metapackage requiring the exact matching
`sciaiot-rivet` core version. It does not include the API extra or duplicate
the implementation. Install the API and agent in separate environments as
described in [native deployment](../deployment.md#native-installation). Optional Azure,
MySQL, and PostgreSQL extras remain available on `sciaiot-rivet`.

Do not install the unrelated PyPI distribution `rivet`. The `rivet` command
also exists in other projects; use dedicated virtual environments or absolute
paths to the command from this distribution.

The GitHub repository URLs still point to `scia-iot/ovpncp`: renaming the
hosted repository and publishing the new packages/images are separate
release operations. Configure PyPI trusted publishing for **both** new
distributions before running the package release workflow. The workflow
builds their wheels and source distributions together; bump both versions
and the agent's exact core requirement in the same release.

## Existing installations

This is an explicit configuration migration. There are no old Python import,
CLI, or environment-variable aliases. Do not mix old and new API, agent,
OpenVPN-hook, and UI artifacts.

1. Retain the previous release's deployment files, images or wheels, and a
   verified recovery set. Stop the old services and all writers before
   copying or changing state. Keep the API database, archives, VPN state,
   journal, and ownership records together.
2. Build all four Rivet images or the two Python distributions. Select exact
   versions/digests and collect fresh capability evidence. Historical image
   hashes and pre-rename rehearsal results do not validate the renamed
   images. The hook's Python import changed, so its checksum changed too.
3. Translate `OVPNCP_*` settings to `RIVET_*` using the new templates. Keep
   existing `AZURE_*`, `VITE_*`, database settings, and numeric service
   identities. Regenerate `runtime-config.js`: the browser now reads
   `window.__RIVET_CONFIG__`. Deploy UI assets and runtime config together.
4. For native installations, install fresh virtual environments under
   `/usr/local/lib/rivet`, export the new templates, and review units and
   settings under `/etc/rivet`. Copy the **complete stopped** API directory
   from `/opt/ovpncp` to `/opt/rivet`, retaining owners, permissions, database
   sidecars, archives, and the client profile. Keep the old copy for rollback.
   Update Nginx, static asset paths, and OpenVPN hook commands to the new
   absolute `rivet-vpn-event` path. Review paths in both authoritative and
   projected configuration; preserve their journal identity anchors.
5. For Compose, stop the old project using its original Compose files and
   environment. The new default project name is `rivet`; it does not stop
   containers belonging to `ovpncp`. Use `RIVET_STATE_ROOT` to retain the
   existing host bind-mount root. The API mount target changes to
   `/opt/rivet`; the host `api-data` and `api-archives` layout is unchanged.
   Review hook paths in authoritative and projected server configuration
   before starting new images. An encrypted VPN migration can instead map
   the reviewed source hooks to the Rivet target hook.
6. Disable the old native units before enabling the new ones. Start only one
   stack. Verify API readiness, agent peer identity, certificate inventory,
   client connectivity, revocation enforcement, and firewall ownership. To
   roll back, stop Rivet and restore the original release with its complete
   retained state and deployment settings.

The source-capture adapter recognizes the exact old container hook command
and checksum as well as the Rivet hook. Arbitrary commands or changed hook
bytes are rejected. New container targets require the Rivet hook checksum.
Existing encrypted bundles remain readable, but target replacement policies
must name and checksum the new hook. Full recovery sets retain their original
configuration bytes; restoring one alone does not rewrite hook paths or
perform this deployment migration.

## Stable internal identifiers

The following identifiers deliberately retain `ovpncp` for data and ownership
compatibility. Do not rename them during deployment:

- `ovpncp.db` and its SQLite sidecars;
- encrypted migration/recovery format magic and schema versions;
- `.ovpncp-migration.json`, `.ovpncp-journal-identity`, and
  `ovpncp-deleted.json`;
- the `OVPNCP_FORWARD` chain, `ovpncp:` rule comments, and managed CCD blocks;
- the Azure Blob Storage container `ovpncp`.

VPN service accounts (`ovpn-api`, `ovpn-agent`, `ovpn-openvpn`), groups,
socket paths, and `/var/lib/ovpn-agent` remain unchanged. They define
permissions and persistent state ownership rather than product branding.
No deployment host is modified by the repository rename.
