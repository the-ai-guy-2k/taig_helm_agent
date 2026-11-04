#!/bin/sh
# TAIG Helm Agent — Droplet install. Run on the Droplet, from this repo.
# Dev install, Droplet only. Does not touch client or lab boxes.
set -eu
cd "$(dirname "$0")"
mkdir -p /opt/taig-helm-agent /var/lib/taig-helm-agent
cp agent.py /opt/taig-helm-agent/agent.py
chmod +x /opt/taig-helm-agent/agent.py
# 30-second status writer, via cron (cron runs at minute granularity,
# so this job runs every minute and the agent also runs on demand over SSH).
# The status file is overwritten each run, so it never grows.
( crontab -l 2>/dev/null | grep -v "taig-helm-agent/agent.py write-status" || true; \
  echo "* * * * * python3 /opt/taig-helm-agent/agent.py write-status >> /var/log/taig-helm-agent.log 2>&1" ) | crontab -
if [ -f logrotate/taig-helm-agent ]; then
  cp logrotate/taig-helm-agent /etc/logrotate.d/taig-helm-agent 2>/dev/null || true
fi
python3 /opt/taig-helm-agent/agent.py write-status
echo "TAIG Helm Agent installed. Status file: /var/lib/taig-helm-agent/status.json"
