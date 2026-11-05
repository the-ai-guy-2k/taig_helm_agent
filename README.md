# TAIG Helm Agent — Droplet side

Dumb on purpose. The agent gives the laptop relevant info from the box,
and (after the v1 proof) runs approved structured tasks. It does NOT
decide, it does NOT verify a change, and it never runs a free-form
shell string from the GUI.

- Laptop decides. Laptop verifies by re-reading box state, NOT by
  exit code alone. Laptop logs every command it sends.
- Monitoring: this agent writes a status file constantly (see below).
  The laptop requests/polls it. The laptop is NOT reachable from the
  internet, so there is NO push from the laptop side.

## v1 proof — what this repo does

`agent.py status` — fresh CPU / memory / storage as JSON, to stdout.
`agent.py write-status` — same JSON, written atomically to the status
file, overwriting it. Single file, overwritten every run, so it never
grows — that is the rotation/cap for v1.
`agent.py version` — version only.

Task execution is NOT in v1. `agent.py task` fails on purpose.
After the v1 dashboard proof passes, task flow lands as:
info -> decide -> send -> execute -> verify -> log, with structured
payloads only, preview-approve gate on the laptop, verification by
state re-read on the laptop.

## Firewall — first feature after v1 (Nov 4, 6:38 PM EST)

- `agent.py firewall list` — INPUT policy, INPUT rules, listening ports.
- `agent.py firewall add --action allow|deny --protocol tcp|udp --port N --source CIDR|any`
- `agent.py firewall remove --action ... --protocol ... --port ... --source ...`
- Guards, enforced here before iptables: never deny SSH port 22,
  INPUT chain only, removal only for Helm-managed rules
  (comment `taig-helm`), never DOCKER chains, UFW is inactive so this
  is direct iptables. All args are validated; no free-form shell.
- Persistence: NOT installed here. Rules are runtime only until Tee
  decides in main chat (install iptables-persistent, or save another
  way). Do NOT install it from this repo without that main-chat go.

## Files

- `agent.py` — stdlib only, no dependencies, no network listener.
- `install.sh` — Droplet install: copies agent.py to
  `/opt/taig-helm-agent/agent.py`, creates `/var/lib/taig-helm-agent/`,
  installs a 30-second cron job running `write-status`.
- `logrotate/taig-helm-agent` — caps the writer log at 1 MB, 3 rotations.
  The status file itself needs no rotation: it is overwritten, not appended.
- `test_agent.py` — checks status JSON shape locally, no Droplet needed.

## Updates — second feature after v1 (Nov 4, 6:55 PM EST)

- `agent.py updates check` — runs apt-get update (lists only, no
  install), then lists upgradable packages with current/new versions
  and a best-effort security flag. Check NEVER installs anything.
- `agent.py updates apply --scope whole` — apt upgrade only (never
  dist-upgrade, never release upgrade, never Docker).
- `agent.py updates apply --scope one --package NAME` — apt install
  --only-upgrade NAME, only if NAME is in a FRESH checked list, done
  inside the apply call. Any other package name is refused.
- No free-form apt string, ever. Package names are validated and
  allowlisted. Unattended-upgrades status is reported, not changed.

## Logs — third feature after v1 (Nov 4, 7:17 PM EST)

- `agent.py logs list` — plain-name allowlist: system, sign-ins,
  kernel, package changes, update history, automatic security
  updates, first-boot setup, website visits/errors, Helm agent
  (files), plus Docker containers pia, nope-portal, taig-speed, tsp.
  Returns exists/size for files, container presence for Docker.
- `agent.py logs read --service KEY [--lines N] [--search TERM]
  [--since-hours 1|24|168]` — READ-ONLY, always. No delete, no
  truncate, no restart, no free-form tail/cat/docker string.
  Search is plain words/numbers only (shell characters rejected).
  Time filter is exact for Docker (--since) and best-effort for
  plain files (lines without a readable timestamp are kept).
  Scans the last 10,000 lines, returns the requested tail.

## Install on the Droplet (pull-only flow)

```sh
# On the Droplet, as the operator, from the repo checkout:
git clone https://github.com/the-ai-guy-2k/taig_helm_agent.git
cd taig_helm_agent
# Note: GitHub push does not preserve the executable bit reliably,
# so run via sh, not ./install.sh:
sudo sh ./install.sh
python3 /opt/taig-helm-agent/agent.py status
python3 /opt/taig-helm-agent/agent.py firewall list
cat /var/lib/taig-helm-agent/status.json
```

Do NOT install this on a client box or lab machine. Droplet only, for v1.

## How the laptop reaches it

The laptop's local service runs SSH with a FIXED command, e.g.:

```sh
ssh -i ~/.ssh/<your-key> <user>@138.68.226.24 \
  "python3 /opt/taig-helm-agent/agent.py status"
```

No other remote command is sent in v1. The agent path, user, and host
live in the laptop's local config, never in the GUI, never as user input.
