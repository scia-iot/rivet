# Read-only VPN agent and shadow operation

Phase 3 adds `ovpncp-vpn-agent` (also `python -m
sciaiot.ovpncp.vpn_agent`). It observes a single OpenVPN 2.6 IPv4/TUN server.
It cannot issue, renew, revoke, delete, package credentials, assign addresses,
change routes/rules, acknowledge events, disconnect sessions or reload VPN.
There is only `POST /v1/control` on a private Unix socket. Unsupported commands
receive a correlated protocol `unavailable` failure; there is no archive route.
Malformed requests without a trusted correlation ID are closed.

Keep production on `host`. An operator can opt into `shadow` on a prepared
disposable deployment to compare reads while retaining every legacy response
and mutation path. Shadow calls have a 500 ms total client budget and report
only command kind and `match`, `mismatch` or `unavailable`; no values, names,
addresses, hashes, paths, credentials or exception details are logged. Agent
loss leaves the original host result intact. After a failed comparison, that
shadow adapter defers further attempts for five seconds, bounding repeated
outage delay during a legacy discovery workflow. No management write is sent.
Agent-only API mode cannot serve lifecycle workflows until Phase 4 exists.

## Explicit configuration

The agent loads these variables once at startup. No request can select a file,
executable, command argument, identity or environment variable.

| Variable | Meaning |
| --- | --- |
| `OVPNCP_AGENT_CONFIG` | Absolute server configuration file; single-file syntax. |
| `OVPNCP_AGENT_PKI` | Absolute public PKI observation root containing `ca.crt`, `index.txt`, and `issued/*.crt`. Private keys are never opened. |
| `OVPNCP_AGENT_CCD` | Absolute CCD observation directory. |
| `OVPNCP_MANAGEMENT_SOCKET` | Canonical private OpenVPN management Unix socket. |
| `OVPNCP_MANAGEMENT_UID` | Expected listener creator UID from Linux `SO_PEERCRED`; OpenVPN startup UID may be 0 even after dropping privileges. |
| `OVPNCP_MANAGEMENT_GID` | Expected listener primary GID and private parent directory GID. |
| `OVPNCP_API_UID` | The sole API peer UID allowed to send control requests. |
| `OVPNCP_AGENT_SOCKET` | Defaults to `/run/ovpn-agent/agent.sock`. |
| `OVPNCP_AGENT_OWNERSHIP` | Optional operator-provided read-only ownership manifest described below. |

Prepare the control parent directory with agent ownership, control group, mode
02750. The server refuses an existing socket, creates its own mode 0660 socket,
and removes only that socket on shutdown. API mounts the directory read-only.
Linux peer credentials are checked before reading any HTTP header/body. Agent
client independently authenticates the server UID before sending bytes.
Directories and observation files cannot be symlinks, including ancestors.
Observation files must be regular with exactly one hard link, are opened
no-follow, have bounded reads,
and are rejected if their size/mtime/ctime changes during a read. Client
inventories require two identical bounded observations to detect cross-file
drift; network inspection rechecks its ownership inventory before publication.

OpenVPN configuration must contain exactly one `management <socket> unix`,
`management-client-user <agent-user>` and `management-client-group
<agent-primary-group>`. Account names resolve to the running agent identity.
Other `management-*` options fail readiness, including management signal,
client mode, hold and password querying. The management parent must exclude
other-user access and have the explicit runtime group. Both peer UID and GID
are verified before sending one of the fixed `version`, `state`, or `status 3`
commands. Exchanges are serialized and connections are closed after each.
There is no TCP fallback. Readiness requires OpenVPN 2.6, `CONNECTED,SUCCESS`,
the configured TUN link up, the explicit `nf_tables` compatibility backend,
and successful verification of all declared owned network state.

## Observation and ownership limits

Configuration includes/inline blocks, unnumbered `dev tun`, ambiguous scalar
options and unsupported typed values fail closed. Configuration is projected
into protocol fields; private paths and raw options never leave the agent.
Only signed client-auth leaf certificates directly issued by the configured
CA are discovered. Names must match certificate CNs and the CA index must
contain each observed serial. State is observed from the CA index; server
certificates are excluded. CCD address and optional single iroute are typed.
This is observation, not complete migration/PKI validation or a recovery set.
Use the M0 toolkit for complete authenticated migration and restore evidence.

An absent ownership manifest means zero owned routes/rules/pushes. Legacy
network entries are never automatically adopted. The strict manifest is:

```json
{
  "version": "1.0",
  "routes": [],
  "access": [],
  "pushes": []
}
```

Rows use protocol `ManagedRoute`, `AccessIntent` and `OwnedPushes` schemas.
Duplicate ownership identities, unknown fields and duplicate JSON keys fail.
The operator must review this inventory and reserve route protocol **200** for
these entries; this read-only service neither creates markers nor writes an
ownership journal. Each route must actually match device, destination,
gateway, unicast type and protocol 200. Matching foreign routes are rejected.

The expected filter chain is `OVPNCP_FORWARD`, reached from exactly the owned
FORWARD anchors `-i <dev>`/`-o <dev>` with comments
`ovpncp:anchor:ingress`/`ovpncp:anchor:egress`. Each access pair has source and
destination `/32` ACCEPT rules with comments
`ovpncp:<access_id>:forward`/`ovpncp:<access_id>:reverse`. Optional private
networks use source `/32` to private network and the reverse, with comments
`ovpncp:<access_id>:private:<zero-based-index>:forward`/`reverse`.
All rules use `-m comment --comment <marker> -j ACCEPT`; anchors jump to the
owned chain. Missing, duplicate, incomplete or unexpected owned-chain rules
fail inspection. Foreign rules outside the owned namespace are ignored.
Declared pushes must belong to a declared access intent/client and occur
exactly once in that client's CCD. No packet is sent and no rule is changed.

Observation revisions are content-derived 63-bit values over typed public
observations, not monotonically increasing mutation journal generations.
Health carries the sanitized configuration revision.
Client revisions include certificate state and assignment; page revisions
cover the complete observed collection. Cursors bind collection revision and
offset and fail after observed drift. Session IDs are derived from the agent's
random lifetime epoch and stable status identity fields; repeated observations
retain IDs, and restarting the read-only agent changes them. Traffic counters
do not change session revisions. No session IDs authorize disconnect in Phase 3.

Each control connection permits one request. Header/body receipt has a two
second total budget, and execution is capped at the lesser of the request
deadline and ten seconds. One active request and a kernel backlog of 16 avoid
unbounded threads. JSON, individual files, management and subprocess output
are bounded to 1 MiB (certificates 64 KiB); inventories have at most 10,000
records and 16 MiB of certificate bytes. Pages contain at most 100 items.
Subprocess output is bounded while reading, with deadline kill/reap and closed
pipes. The only fixed executables are `ip` read commands and
`iptables-nft-save` filter/version reads. Firewall inspection requires the
deployment's reviewed NET_ADMIN grant, even though no mutation is implemented.

## Image and verification

`deploy/agent/Dockerfile` is the minimal first-party development image. Build
from the repository root with `docker build -f deploy/agent/Dockerfile .`.
It contains protocol/agent code, Pydantic, cryptography, iproute2 and iptables;
it excludes the API, Azure integrations and PKI mutation utilities. It declares
the nonroot `ovpn-agent:ovpn-runtime` identity 65532:65532; allocate compatible
deployment identities or derive a reviewed image with the desired account IDs.
It exposes no TCP port. Deploy with read-only root, no-new-privileges, bounded
tmpfs, only reviewed capabilities and service-specific read-only state mounts.
It needs no TUN device, database, cloud credentials or container-runtime socket.
Immutable base/dependency pinning, SBOM, signature, scanning and exact image
runtime grant evidence remain Phase 5/6 gates. A Dockerfile alone is not that
proof; no local/remote builder was available during Phase 3 verification.

Unit tests use disposable signed public PKI, fake network observations and
real local Unix sockets. The separate
`tests/integration/run_vpn_agent_namespace.sh` rehearsal requires the same
private mount/network/PID namespace attestation as M0 and synthetic state.
Only run it on explicitly authorized disposable infrastructure. It does not
authorize production state access or changes. Rollback consists of stopping
the agent and setting the API backend back to `host`; VPN lifecycle and all
legacy state remain host-owned throughout this phase.

The verified namespace command has this form. Set all three paths to reviewed
absolute paths outside `/tmp`, `/run` and live OpenVPN roots; prepare the
optional evidence directory as root-owned mode 0700. The interpreter must have
this repository's development dependencies. This is an explicitly privileged
verification command for a disposable authorized host, not agent deployment:

```sh
agent_repository=/absolute/reviewed/checkout
agent_python=/absolute/python314/venv/bin/python
agent_evidence=/absolute/private/evidence
sudo -n timeout --signal=TERM --kill-after=10s 600s \
  unshare --mount --net --pid --fork --kill-child --propagation private \
  /bin/sh "$agent_repository/tests/integration/run_vpn_agent_namespace.sh" \
  "$agent_python" "$agent_repository" /usr/share/easy-rsa/easyrsa \
  "$agent_evidence"
```
