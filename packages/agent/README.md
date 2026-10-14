# Rivet agent from SCIA IoT

`sciaiot-rivet-agent` installs the matching `sciaiot-rivet` core release
without the optional API, database, or Azure dependencies. The core provides
the `rivet-agent`, `rivet-vpn-event`, `rivet-migrate`,
`rivet-export-native`, and `rivet-native-firewall` commands. No application
code is duplicated in this metapackage.

Install the same release as the API:

```bash
python -m pip install sciaiot-rivet-agent
```

The agent requires Linux, OpenVPN, Easy-RSA, and reviewed service permissions.
See the native installation section of `docs/deployment.md` for setup.
The archived `docs/archive/rivet-rename.md` covers upgrades from ovpncp.

Release versions and the exact core dependency are set from the GitHub release
tag during packaging. Source checkouts use `0.0.0.dev0` until prepared with
`python deploy/release_version.py --tag vX.Y.Z --write` from the repository root.
See [builds and releases](../../docs/builds.md#native-python-and-ui-artifacts).
