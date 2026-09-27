#!/bin/sh
# OpenVPN removes inherited Python variables before running hooks.
export PYTHONPATH=/opt/agent
exec /usr/local/bin/python -m sciaiot.ovpncp.vpn_agent.event_hook "$@"
