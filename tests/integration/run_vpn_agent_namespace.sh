#!/bin/sh
# Isolated Phase 3 rehearsal; reuses the tested M0 namespace attestation.
set -eu
umask 077
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo 'Expected: absolute-python absolute-repository absolute-easyrsa [private-failure-evidence-dir]' >&2
    exit 2
fi
agent_python=$1
agent_repository=$2
agent_easyrsa=$3
for agent_input in "$agent_python" "$agent_repository" "$agent_easyrsa"; do
    case "$agent_input" in
        /tmp|/tmp/*|/run|/run/*|/etc/openvpn|/etc/openvpn/*)
            echo 'Inputs must be outside ephemeral and live OpenVPN roots.' >&2
            exit 2 ;;
        /*) ;;
        *) echo 'Inputs must be absolute reviewed paths.' >&2; exit 2 ;;
    esac
done
if [ "$(id -u)" -ne 0 ]; then
    echo 'Namespace setup requires reviewed root execution.' >&2
    exit 2
fi
for agent_namespace in net mnt pid; do
    if [ "$(readlink "/proc/self/ns/$agent_namespace")" = "$(readlink "/proc/1/ns/$agent_namespace")" ]; then
        echo 'Refusing initial host namespaces.' >&2
        exit 2
    fi
done
# These commands only run after all namespace identities differ from PID 1.
mount --make-rprivate /
mount -t tmpfs -o mode=0700,size=16m,nosuid,nodev,noexec tmpfs /run
mount -t tmpfs -o mode=0700,size=256m,nosuid,nodev,noexec tmpfs /tmp
if [ -d /etc/openvpn ]; then
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev,noexec tmpfs /etc/openvpn
    mount -o remount,ro /etc/openvpn
fi
printf '%s\n' 'DISPOSABLE OPENVPN MIGRATION NAMESPACE' > /run/ovpncp-disposable-runner
# Per-process limits and the caller's outer timeout bound the test workload.
ulimit -c 0
ulimit -n 256
ulimit -f 131072
ulimit -v 2097152
ulimit -t 300
if [ "$#" -eq 4 ]; then
    set -- --failure-evidence-dir "$4"
else
    set --
fi
exec env PYTHONPATH="$agent_repository/src:$agent_repository" "$agent_python" \
    "$agent_repository/tests/integration/vpn_agent_rehearsal.py" \
    --easyrsa "$agent_easyrsa" "$@"
