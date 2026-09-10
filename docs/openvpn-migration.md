# Portable OpenVPN migration toolkit

Phase M0 is **complete for the documented stopped-target migration profile**.
The typed CLI supports reviewed file-based, direct-CA OpenVPN/Easy-RSA
configurations. Unit/security tests, an independent real Easy-RSA offline
integration and a real UDP/TUN migration rehearsal on a separately isolated
Linux server passed. The real rehearsal used unchanged client credentials,
observed the migrated CCD assignment, exercised target issuance/revocation/CRL
generation and restored the exact nonempty prior target state. This is toolkit
acceptance evidence, not approval to migrate a live installation or cut over
production traffic.

The tool does not migrate ovpncp, its database, archive storage, authentication,
UI, system services, host accounts, routes, firewall rules or cloud resources.
It invokes no system commands. It neither stops services nor freezes external
writers automatically. Its supported target adapter starts and ends with the
target OpenVPN process **stopped**; a previously running service needs an
operator-controlled maintenance and recovery procedure outside this adapter.

## Install and command contract

Install the project with its existing runtime dependencies. No new dependency
is required: authenticated encryption uses the existing `cryptography` package.
The installed command is `ovpncp-migrate`; from a checkout use
`PYTHONPATH=src python -m sciaiot.ovpncp.migration.cli`.

All six subcommands emit redacted JSON. Success exits 0; validation, input,
compatibility and operational failures exit 2. Errors contain safe corrective
messages and never echo input documents, identities, network addresses, private
paths, private keys or passphrases. All commands are non-interactive. `--help`
describes flags; there are no implicit confirmations or environment secrets.

| Command | Effect |
| --- | --- |
| `inventory --source source.json` | Discover file counts, versions, directive names and excluded runtime directive names. No consistent-snapshot or PKI-validation claim. |
| `export --source source.json --bundle migration.bundle --key-file migration.key --writers-frozen` | Capture and validate a consistent complete PKI/configuration snapshot, then exclusively create an encrypted mode-0600 bundle. |
| `validate --bundle migration.bundle --key-file migration.key --policy target.json` | Authenticate, parse, validate PKI/hashes/semantics and compare observed target capabilities. No target access or writes. |
| `import --bundle migration.bundle --key-file migration.key --policy target.json --target /srv/migration` | Validate and report a dry-run by default. |
| Same `import` with `--apply --target-stopped` | Stage and atomically activate into an explicit migration-owned target while preserving mandatory rollback state. |
| `verify --bundle migration.bundle --key-file migration.key --policy target.json --target /srv/migration` | Compare exact rendered target files and protected CA/server/client/CCD/options inventory. |
| `rollback --target /srv/migration` | Report rollback availability without changes. |
| Same `rollback` with `--apply --target-stopped` | Restore the prior active tree's exact hashes, modes and owners; remain stopped. |

`export`, `validate`, `import`, and `verify` also accept
`--pki-passphrases-file private-passphrases.json` for encrypted private keys.
The mode-0600 JSON file has this shape (use actual secrets only in the private
file, never command arguments):

```json
{"keys": {"pki/private/ca.key": "secret supplied through protected file"}}
```

Passphrases are held in process memory, excluded from all manifests, and must
be supplied again for each invocation that validates encrypted keys. Original
encrypted key bytes are preserved. Inventory does not need key passphrases.

## Source approval and mutation freeze

The source descriptor is private operational input. `openvpn_root` and
`easyrsa_root` are explicit approved directory roots, including all referenced
files. Absolute references must remain inside an approved root; relative
OpenVPN references resolve against `openvpn_root`. Parent traversal, symlinks,
hard links, sockets, FIFOs and device nodes are rejected. Roots and parent
components are opened without following symlinks. A nested config may include
another config; includes are bounded to 16 levels and cycles are rejected.

```json
{
  "openvpn_root": "/approved/openvpn",
  "easyrsa_root": "/approved/easy-rsa",
  "pki_subdirectory": "pki",
  "easyrsa_config": {
    "openssl-easyrsa.cnf": "openssl-easyrsa.cnf"
  },
  "server_config": "server.conf",
  "versions": {
    "openvpn": "2.6.12",
    "easyrsa": "3.2.1",
    "openssl": "3.5.4"
  },
  "serial_policy": "random"
}
```

Version values above are examples. Record exact versions observed on the source
and target, including OpenVPN and crypto build capabilities. If the Easy-RSA
root is the PKI directory itself, omit `pki_subdirectory`. The optional
`easyrsa_config` mapping captures the required OpenSSL configuration and
optional `vars` from the approved installation root into logical PKI entries.
The complete current PKI tree is inventoried, including issued and historical
certificates, private keys, requests, index and serial backups, CRL in PEM/DER,
inline credential state and empty directories. Unknown artifacts fail rather
than being silently skipped.

Before `--writers-frozen`, disable every source mutation path: API/agent/CLI
certificate operations, scheduled issuance/revocation/CRL jobs, CCD writers,
configuration management and pool persistence writes. An operator must ensure
this across all processes. A lock that only this tool knows cannot enforce it.
Existing VPN connections may stay up only when the operator can prevent every
persistent source write; otherwise stop the source daemon for the snapshot.
The flag attests that this procedure has already happened. The tool reads twice
and rejects inconsistent snapshots; this is additional detection, not a
replacement for the external freeze. Source files are never edited.

## Compatibility and target mapping

Schema 1 fails closed on version differences. There is no blanket `--force` or
unreviewed cross-version transformation. A changed source profile requires a
reviewed, tested transformation and a future schema/implementation change.

The target policy records exact observed versions, the source serial allocation
policy, existing target owner/group **names**, and option/cipher availability.
An example minimal policy for a server without additional directives is:

```json
{
  "versions": {
    "openvpn": "2.6.12",
    "easyrsa": "3.2.1",
    "openssl": "3.5.4"
  },
  "serial_policy": "random",
  "owner": "",
  "group": "",
  "supported_options": [
    "dev", "proto", "port", "server", "ca", "cert", "key",
    "crl-verify", "dh", "client-config-dir"
  ],
  "supported_ciphers": ["AES-256-GCM", "AES-128-GCM"],
  "replacements": {}
}
```

Observe the target binary's version, help/options and cipher/TLS-cipher lists
privately and review the required entries. The toolkit checks that every
source option and explicitly configured cipher is supported according to that
policy. It does not invent observations or run a target binary itself. A
policy copied from the source is not independent capability evidence. Omitted
owner/group names use the invoking operator's identity; numeric source IDs are
never imported. The offline adapter requires the target owner to be the
migration operator: its mode-0700 destination protects active state, rollback
and journal, so another user cannot traverse it. A separately owned runtime
needs reviewed bind mounts/runtime-path mapping in a future target adapter;
this CLI rejects that unsupported mapping rather than creating unreadable
state. The example leaves ownership at the invoking identity.

Configuration paths become logical entries and are rendered for
`TARGET/active/...`. Source user/group, logging, status, PID, daemon and
management-socket options are excluded from the active config; their names
remain in the sanitized inventory. Configure target runtime identities,
management, status and logging through reviewed target-version service code.
Source hooks are hashed and inventoried, never bundled. Each required hook
needs a `replacements` entry keyed by its protected `option:SHA256` identity:

```json
{
  "client-connect:source-script-sha256": {
    "path": "/reviewed/target/client-connect",
    "sha256": "reviewed-target-code-sha256"
  }
}
```

Inspect hook identifiers privately from authenticated bundle metadata through
the typed API; never print the sensitive manifest as routine CLI output. The
target code must already exist, stay outside migration state, and match the
reviewed hash. Arbitrary hook argument strings are rejected.

Supported PKI verification includes CA/server fingerprints, signature chains
to a direct self-signed CA, key matches, server validity/usage, complete index
and serial allocation consistency, fresh signed CRLs, and existing/revoked
client status. Revoked clients deleted by ovpncp may have no remaining leaf
certificate or private key; their index/CRL evidence is retained. Expired
historical client certificates remain historical state. The server and CA
must be currently valid. Both sequential and Easy-RSA random serial allocation
policies are explicit; a random next serial is not required to exceed every
previous serial.

The initial compatibility boundary deliberately rejects:

- `cd`, inline OpenVPN blocks, CRL directories, TLS-crypt-v2 keys, plugins,
  complex hook arguments and unknown directives;
- intermediate/external CAs and inconsistent or stale PKI;
- executable Easy-RSA `vars` expressions and host-specific OpenSSL
  include/engine/provider/module settings;
- unreviewed application, database, archive, UI or executable artifacts.

`vars` supports reviewed declarative `set_var` assignments only. Stock
Easy-RSA OpenSSL configuration can use its PKI environment variables, but
absolute source paths and external include/code-loading behavior are refused.
These profiles are outside the completed compatibility policy. Supporting one
requires a reviewed extension and its own migration evidence before that
profile is used. Do not decrypt/rewrite the sole CA key or edit the live source merely
to work around an unsupported migration profile.

## Encryption and schema

Generate an independent 32-byte cryptographically random AES key in a private
directory, with umask 077, using an approved secret-delivery mechanism. A local
example is `openssl rand -out migration.key 32` after setting `umask 077`.
The key file must have no group/other permission bits. Supply the file path,
never key bytes, on the command line. Transfer keys separately using the
approved secret channel. The bundle is always encrypted before it is written;
no plaintext archive is staged. Keep source, staging, snapshot and target
volumes on encrypted storage because active PKI is necessarily readable there.

The byte envelope is:

1. fixed `OVPNCP-MIGRATION\0\1AES256GCM\0` header;
2. fresh 12-byte cryptographic nonce;
3. AES-256-GCM ciphertext and 16-byte authentication tag, authenticating the
   fixed header as associated data.

The encrypted payload is uncompressed USTAR containing one `manifest.json`
and regular `files/<logical-path>` entries. Schema 1 stores component versions,
serial policy, main config, logical files and directory inventory, SHA-256
hashes, byte sizes, required mode 0600, logical owner `vpn-state`, parsed
configuration references, excluded runtime option names, hook hashes, and
protected certificate fingerprints/serials/validity/revocation/CCD/options.
Unknown schema versions and duplicate JSON fields are rejected. The outer
AEAD authenticates all manifest and archive bytes; checksums are an additional
consistency check.

Limits: 10,000 files, 16 MiB per file, 128 MiB total logical contents, 144 MiB
maximum encrypted artifact including bounded metadata/padding, 512-character
logical paths, 8,192-character configuration lines/arguments, and 16 nested
includes. Archive members must be USTAR regular files with mode 0600 and
logical ownership metadata; duplicates, absolute paths, traversal, links,
devices, extension records, compression, trailing hidden bytes and unexpected
entries are refused. No archive extraction API is used.

## Activation and recovery

Use a fresh mode-0700 destination or an exact previously migration-owned root.
A non-empty arbitrary directory is refused. Successful initialization writes
an exact-destination ownership marker. Every file is staged mode 0600 and
every directory mode 0700; owner/group names are resolved locally. Staging is
on the destination filesystem. The toolkit validates protected source data
before staging, compares every staged hash, revalidates before activation, and
compares the active rendered tree afterwards.

The target structure contains `active`, a retained `rollback` tree when a
prior active generation existed, a private lock, ownership marker, and durable
rollback journal. For a clean target, the journal records that the prior active
tree did not exist. The journal is fsynced before atomically renaming an old
active tree to rollback and the stage to active. Each rename is atomic; the
sequence has an intentional gap that is safe only with the target stopped.

Caught activation failures restore the prior tree automatically. After a
process crash, freeze target writers, keep the target stopped, and run
`rollback --apply --target-stopped`. The journal supports crashes before or
after either rename. A corrupt snapshot is retained and refused instead of
silently claiming restoration. A crash before the journal was written may
leave a private `.stage-*` directory; preserve evidence and have an operator
remove only that reviewed abandoned stage after confirming no journal and no
active-state change. Never delete the only PKI copy.

A retained snapshot blocks another import. There is intentionally no automatic
snapshot pruning or implicit commit. Verify semantic state and existing client
connectivity before target PKI mutation tests. Issuance/revocation necessarily
changes target hashes, so afterwards compare preservation of original
credentials and revocations separately; do not expect the original exact-hash
`verify` to pass after intentional mutations. Retain the rollback snapshot
through the full rehearsal and operator acceptance. Snapshot retirement and
service cutover remain reviewed operational steps.

## Reproducible rehearsal and acceptance evidence

Ordinary `pytest` performs no privileged operations. The opt-in harness lives
at `tests/integration/migration_rehearsal.py` and is not pytest-collected. Its
offline mode requires a reviewed installed Easy-RSA executable and OpenSSL:

```bash
PYTHONPATH=src python tests/integration/migration_rehearsal.py \
  --mode offline --easyrsa /reviewed/easy-rsa/easyrsa \
  --declared-openvpn-version 2.6.12
```

It generates a private disposable CA, server, existing client and already
revoked client; runs encrypted export/validate/dry-run/import/verify; issues
and revokes a new test client in the imported PKI; checks unchanged existing
credentials and preserved revocations; rolls back; and checks source hashes.
Only synthetic PKI is touched. Artifacts/logs remain in a private
`/tmp/ovpncp-migration-rehearsal-*` directory. Redacted JSON labels OpenVPN
metadata as a declared assumption and connectivity as unverified.

The network variant is **not to be run in the current macOS-hosted development
container**. Use a reviewed Linux server with TUN, OpenVPN, Easy-RSA, OpenSSL,
iproute2, namespace privileges, and a private Python 3.14 runtime. An existing
VPN on that server must remain untouched. Stage the reviewed code and runtime
outside `/tmp`, `/run`, and the live `/etc/openvpn` tree. Never create the
rehearsal marker in the host's `/run`.

The namespace launcher refuses execution unless its mount, network and PID
namespace identities all differ from the original host PID 1. It then makes
mount propagation private, mounts private bounded tmpfs at `/run` and `/tmp`,
masks `/etc/openvpn` with a read-only private tmpfs, and creates the marker
only inside the new `/run`. The Python harness independently rechecks namespace
identities, mount propagation, distinct tmpfs device identities and the marker
before any network mutation. A reviewed invocation is:

```bash
sudo -n timeout --signal=TERM --kill-after=10s 600s \
  unshare --mount --net --pid --fork --kill-child --propagation private \
  /bin/sh /private/stage/repo/tests/integration/run_migration_namespace.sh \
  /private/stage/runtime/bin/python3.14 /private/stage/repo \
  /usr/share/easy-rsa/easyrsa
```

Use actual reviewed staging paths. Keep the existing `/proc` mount: do **not**
add `--mount-proc`, because comparisons deliberately reference the original
host PID 1. The temporary PID namespace ensures remaining child processes die
when its init exits. The launcher bounds `/tmp` to 256 MiB, `/run` to 16 MiB,
virtual address space to 2 GiB per process, CPU to 300 seconds per process,
file descriptors to 256, and suppresses core dumps; the outer timeout bounds
the overall run. Private tmpfs data disappears when the namespaces exit. For diagnosis, the
operator may precreate an empty root-owned mode-0700 evidence directory inside
the approved persistent staging area and pass it as a fourth launcher argument.
The harness validates it before execution and, on failure only, retains bounded
`commands.log`, `server.log`, and `client.log` with mode 0600. It never copies
arbitrary PKI files. Without that explicit argument, no failure logs leave the
private tmpfs. Console failures include only allowlisted tool/stage labels,
exit code and a classified reason; raw command output remains private.

The harness starts only its own server/client subprocesses, disables DCO when
the binary supports that flag, and changes only the private namespace's
loopback and TUN interfaces. It confirms authentication over UDP with unchanged
source credentials, then observes that the client TUN has its migrated CCD
address. Target option/cipher capabilities come from the actual OpenVPN binary
in network mode. PKI mutations use imported configuration. A synthetic nonempty
pre-import target generation proves exact rollback hashes/modes/owners; the
initial stopped state is restored. No live service manager, firewall rules,
PKI, management sockets or host network configuration are touched.

The namespace-isolated network harness passed on the approved remote Linux
verification server on 2026-09-10. It was not run in the macOS-hosted development
container. The live server's OpenVPN process and network state remained
unchanged. The supported adapter still starts and ends with the target stopped;
previously running services, separately owned runtime mounts and additional
legacy-profile transformations require their own reviewed adapters/policies.


### Recorded evidence (2026-09-10)

An independent manual integration run against official Easy-RSA 3.2.1 source
commit `3f60a68702713161ab44f9dd80ce01f588ca49ac` and OpenSSL 3.5.4 passed
complete capture, encrypted seal/open, immutable dry-run, offline import and
exact/semantic verify. It then issued and revoked a new certificate and
generated a CRL using the imported PKI's own vars and OpenSSL config; existing
client credentials, CA/server identities and earlier revocation remained
unchanged. Rollback and all source file hashes passed. OpenVPN versions and
capabilities were **declared assumptions**; no OpenVPN process or network
operation ran. This evidence came from the manual integration, not a successful
standalone harness run: a source checkout's unrendered `~VER~` version marker
was correctly refused by the harness. Use a properly versioned release artifact
for that harness.

The complete namespace rehearsal subsequently passed at
`2026-09-10T07:11:20.779121+00:00` with OpenVPN 2.6.19, Easy-RSA 3.1.7,
OpenSSL 3.0.13 and Python 3.14.3. OpenVPN version, supported options and ciphers
were observed from the actual binary. Every acceptance field was true:

- encrypted export, authentication/validation, immutable dry-run, staged import
  and exact/semantic verification;
- existing client authenticated over UDP using unchanged source credentials;
- client TUN held the migrated CCD address;
- new target certificate issuance, revocation and CRL generation succeeded;
- pre-existing credentials and revocations were preserved;
- exact nonempty pre-import target hashes/modes/owners were restored, with the
  synthetic target service returned to its initially stopped state;
- every source file hash remained unchanged.

Independent before/after comparisons also matched the live host's links,
addresses, routes, policy rules, normalized IPv4/IPv6 firewall configuration,
and existing OpenVPN process identity/start time. The live host marker remained
absent. No live OpenVPN PKI or configuration was read or migrated. Only synthetic
PKI, private namespace state and the explicitly approved verification staging
area were used. The packaged Easy-RSA 3.1.7 run resolves the earlier standalone
harness version-placeholder gate. Runtime regressions are covered for the
Easy-RSA 3.1 common-name override and OpenVPN's successful `--help` exit code 1.


Final local checks on 2026-09-10: `pytest --cov=src/sciaiot/ovpncp
--cov-report=term-missing` passed **392 tests with 91% overall coverage**.
Migration package coverage is 88%, with each module above 80%. Ruff formatting
and lint pass, `mypy --exclude '^build/' .` passes 62 files, shell syntax checks
pass, and `git diff --check` passes. The mypy exclusion avoids the pre-existing
ignored duplicate `build/lib/sciaiot` package, not any source or test module.
