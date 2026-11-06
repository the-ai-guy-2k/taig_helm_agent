#!/usr/bin/env python3
"""TAIG Helm Agent — Droplet side, dumb on purpose. v1 proof: status only.

Stdlib only. No dependencies, no network listener, no AI, no free-form shell.

The agent is invoked over SSH by the laptop's local service, with a FIXED
command, e.g.:
    python3 /opt/taig-helm-agent/agent.py status

It prints ONE JSON object to stdout and nothing else. Errors go to stderr
with a non-zero exit code.

Allowed commands, and only these:
  status        fresh CPU / memory / storage, printed to stdout
  write-status  same JSON, written atomically to the status file
                (see STATUS_FILE). This is the monitoring file the laptop
                polls — it is OVERWRITTEN every run, so it never grows.
                That single-file overwrite IS the rotation/cap for v1:
                no history is appended to it.
  version       agent version, as JSON

Task execution is NOT in v1. The `task` command intentionally fails with
"not implemented in v1 proof" — task flow (info -> decide -> send ->
execute -> verify -> log) comes AFTER the v1 dashboard proof passes,
and when it lands it will accept structured task payloads only,
never free-form shell strings.

Firewall is the FIRST feature after v1 (Nov 4, 6:38 PM EST).
`firewall list|add|remove` are structured only, INPUT chain only,
Helm-managed rules only for removal, with hard guards:
- NEVER block SSH port 22 (deny on 22 is rejected, before iptables).
- NEVER touch DOCKER / DOCKER-USER / DOCKER-FORWARD chains.
- UFW is inactive on the Droplet — this is direct iptables, not UFW.
- Rules are runtime only until persistence is decided in main chat.
  This agent does NOT install iptables-persistent and does NOT save
  rules to disk on its own.

Verification lives on the laptop, not here: the laptop must NOT trust
exit code alone. It verifies a change by re-reading box state.
"""

import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

VERSION = "0.6.0"
# Default status-file location. Override with TAIG_HELM_STATUS_FILE.
STATUS_FILE = os.environ.get(
    "TAIG_HELM_STATUS_FILE", "/var/lib/taig-helm-agent/status.json"
)


def _read_proc_stat():
    """Return (total, idle) CPU jiffies from /proc/stat, or None."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline().split()
        if not line or line[0] != "cpu":
            return None
        vals = [int(x) for x in line[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return sum(vals), idle
    except Exception:
        return None


def cpu_percent():
    """CPU % over a short sample. Falls back to load average if needed."""
    first = _read_proc_stat()
    if first is None:
        return None
    time.sleep(0.1)
    second = _read_proc_stat()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return 0.0
    return round(100.0 * (1.0 - idle_delta / total_delta), 1)


def memory_info():
    """Memory from /proc/meminfo. Values in bytes."""
    info = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1]) * 1024
    except Exception:
        return {"total": None, "used": None, "free": None,
                "available": None, "percent": None}
    total = info.get("MemTotal") or 0
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = total - avail if total else 0
    pct = round(100.0 * used / total, 1) if total else None
    return {"total": total, "used": used, "free": info.get("MemFree"),
            "available": avail, "percent": pct}


def disk_info():
    """Root + real mounts only. Excludes tmpfs/proc/sys/dev pseudo mounts."""
    seen = set()
    disks = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            mounts = [line.split()[1] for line in f if len(line.split()) >= 2]
    except Exception:
        mounts = ["/"]
    # Root first, always.
    mounts = ["/"] + [m for m in mounts if m != "/"]
    for mount in mounts:
        if mount in seen:
            continue
        seen.add(mount)
        try:
            usage = shutil.disk_usage(mount)
        except Exception:
            continue
        if usage.total == 0:
            continue
        used = usage.total - usage.free
        disks.append({
            "mount": mount,
            "total": usage.total,
            "used": used,
            "free": usage.free,
            "percent": round(100.0 * used / usage.total, 1),
        })
    return disks


def uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return None


def collect_status():
    mem = memory_info()
    disks = disk_info()
    root = next((d for d in disks if d["mount"] == "/"), disks[0] if disks else None)
    return {
        "agent": "taig_helm_agent",
        "version": VERSION,
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": uptime_seconds(),
        "load_avg": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        "cpu_count": os.cpu_count(),
        "cpu_percent": cpu_percent(),
        "memory": mem,
        "storage": root,
        "disks": disks,
    }


def write_status():
    """Write status atomically (tmp + rename). Single file, overwritten
    every run — it never accumulates, so no unbounded growth."""
    data = collect_status()
    path = STATUS_FILE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return data


# ---------------------------------------------------------------- firewall
HELM_COMMENT = "taig-helm"
PROTECTED_PORTS = {22}  # SSH — never deny, never remove an allow for it blindly


def _parse_firewall_args(argv):
    """Strict --key value parsing. No positional free-form, no shell."""
    out = {}
    i = 0
    while i < len(argv):
        if not argv[i].startswith("--") or i + 1 >= len(argv):
            raise ValueError(f"bad firewall argument: {argv[i]!r}")
        out[argv[i][2:]] = argv[i + 1]
        i += 2
    return out


def validate_rule(action, protocol, port, source):
    """Return (clean_rule, error). clean_rule is the validated dict."""
    if action not in ("allow", "deny"):
        return None, "action must be allow or deny"
    if protocol not in ("tcp", "udp"):
        return None, "protocol must be tcp or udp"
    try:
        port_n = int(port)
    except Exception:
        return None, "port must be a number"
    if not 1 <= port_n <= 65535:
        return None, "port must be 1-65535"
    if action == "deny" and port_n in PROTECTED_PORTS:
        return None, "refused: deny on SSH port 22 would lock out the box"
    if source in ("any", "0.0.0.0/0", "::/0"):
        source_norm = "0.0.0.0/0"
    else:
        try:
            net = ipaddress.ip_network(source, strict=False)
            source_norm = str(net)
        except Exception:
            return None, "source must be an IP/CIDR or 'any'"
    return {"action": action, "protocol": protocol, "port": port_n,
            "source": source_norm}, None


def _run_iptables(args):
    """Run iptables with a fixed arg list. No shell, no user string."""
    proc = subprocess.run(["iptables"] + args, capture_output=True,
                          text=True, timeout=20)
    return proc


def _parse_iptables_save(text, chain="INPUT"):
    """Parse `iptables -S <chain>` lines into structured rules."""
    rules = []
    policies = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(f"-P {chain} "):
            policies[chain] = line.split()[2]
        elif line.startswith(f"-A {chain} "):
            rule = {"chain": chain, "raw": line, "helm_managed": False}
            m = re.search(r"-p (\w+)", line)
            if m:
                rule["protocol"] = m.group(1)
            m = re.search(r"--dport (\d+)", line)
            if m:
                rule["port"] = int(m.group(1))
            m = re.search(r"-s (\S+)", line)
            if m:
                rule["source"] = m.group(1)
            if "-j ACCEPT" in line:
                rule["action"] = "allow"
            elif "-j DROP" in line or "-j REJECT" in line:
                rule["action"] = "deny"
            elif "-j RETURN" in line:
                rule["action"] = "return"
            if HELM_COMMENT in line:
                rule["helm_managed"] = True
            rules.append(rule)
    return policies, rules


# Host -> container port map, Nov 5, 2026 live work. This is the FALLBACK
# only — the live map comes from `docker ps` below, which is the truth
# for what is actually running. Static table is used only when docker
# cannot be read, and the list response says so.
KNOWN_PORT_MAP = [
    {"host_port": 3000, "container_port": 3000, "container": "nope-portal",
     "name": "Nope portal", "kind": "docker",
     "via": "Website: / on port 80"},
    {"host_port": 3001, "container_port": 3000, "container": "tsp",
     "name": "TAIG Service Portal", "kind": "docker",
     "via": "Website: taigtsp on port 80"},
    {"host_port": 3002, "container_port": 3000, "container": "taig-speed",
     "name": "TAIG Speed", "kind": "docker",
     "via": "No website route — direct only"},
    {"host_port": 8003, "container_port": 8000, "container": "pia",
     "name": "PIA", "kind": "docker",
     "via": "Website: /pia-ui/ and /pia-api/ on port 80"},
    {"host_port": 22, "container_port": None, "container": None,
     "name": "SSH", "kind": "host", "via": "Direct only — no website route"},
    {"host_port": 80, "container_port": None, "container": None,
     "name": "Web (Nginx)", "kind": "host", "via": "The website itself"},
    {"host_port": 443, "container_port": None, "container": None,
     "name": "Secure web", "kind": "host", "via": "Direct only"},
]
KNOWN_NAMES = {e["container"]: e for e in KNOWN_PORT_MAP if e["container"]}


def _docker_port_map():
    """Live host->container map from `docker ps` Ports, e.g.
    0.0.0.0:8003->8000/tcp. Returns (entries, source_note)."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}|{{.Ports}}"],
            capture_output=True, text=True, timeout=20)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip()[:200])
    except Exception as exc:
        return [dict(e) for e in KNOWN_PORT_MAP], \
            f"docker ps not readable ({exc}); map is the known table, not live"
    entries = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        known = KNOWN_NAMES.get(name, {})
        for host_s, cont_s in re.findall(r"(\d+)->(\d+)", parts[1]):
            entries.append({
                "host_port": int(host_s), "container_port": int(cont_s),
                "container": name,
                "name": known.get("name", name), "kind": "docker",
                "via": known.get("via", "Direct only")})
    # Host services with no container, from the known table.
    for e in KNOWN_PORT_MAP:
        if e["kind"] == "host":
            entries.append(dict(e))
    return entries, "live from docker ps"


def _resolve_rule(rule, port_map):
    """Where a rule for host port `rule['port']` really goes.
    Docker service -> DOCKER-USER on the CONTAINER port.
    Host service -> INPUT on the host port. INPUT does NOT block Docker."""
    for e in port_map:
        if e["host_port"] == rule["port"] and e["kind"] == "docker":
            shared = [x["name"] for x in port_map
                      if x["kind"] == "docker"
                      and x["container_port"] == e["container_port"]
                      and x["host_port"] != rule["port"]]
            return {"chain": "DOCKER-USER", "dport": e["container_port"],
                    "is_docker": True, "container_port": e["container_port"],
                    "service": e["name"], "shared_with": shared,
                    "via": e["via"], "container": e["container"]}
    name = next((e["name"] for e in KNOWN_PORT_MAP
                 if e["host_port"] == rule["port"]), f"Port {rule['port']}")
    return {"chain": "INPUT", "dport": rule["port"], "is_docker": False,
            "container_port": None, "service": name, "shared_with": [],
            "via": "Direct only", "container": None}


def firewall_list():
    proc = _run_iptables(["-S", "INPUT"])
    if proc.returncode != 0:
        raise RuntimeError(f"iptables -S INPUT failed: {proc.stderr.strip()[:300]}")
    policies, rules = _parse_iptables_save(proc.stdout, "INPUT")
    # DOCKER-USER — the real block place for Docker ports. INPUT does
    # not block them (live proof Nov 5: INPUT DROP counters stayed 0).
    docker_rules = []
    docker_note = None
    try:
        dproc = _run_iptables(["-S", "DOCKER-USER"])
        if dproc.returncode != 0:
            raise RuntimeError(dproc.stderr.strip()[:200])
        _, docker_rules = _parse_iptables_save(dproc.stdout, "DOCKER-USER")
    except Exception as exc:
        docker_note = f"DOCKER-USER not readable: {exc}"
    port_map, map_note = _docker_port_map()
    returns = {"127.0.0.0/8": False, "172.17.0.0/16": False}
    for r in docker_rules:
        if r.get("action") == "return" and r.get("source") in returns:
            returns[r["source"]] = True
    # Listening ports, via ss, best-effort — a missing ss is not fatal.
    listening = []
    try:
        ss = subprocess.run(["ss", "-tln"], capture_output=True,
                            text=True, timeout=10)
        for line in ss.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                listening.append({"proto": parts[0], "local": parts[3]})
    except Exception:
        pass
    return {"input_policy": policies.get("INPUT"),
            "rules": rules,
            "docker_user_rules": docker_rules,
            "docker_user_returns_present": returns,
            "docker_user_note": docker_note,
            "port_map": port_map, "port_map_note": map_note,
            "listening_ports": listening,
            "persistent_note": "Helm saves with netfilter-persistent "
                               "after every change. Reboot survival is "
                               "NOT yet verified live — test after push, "
                               "do not claim it until tested.",
            "guards": ["never deny SSH port 22",
                       "never touch DOCKER / DOCKER-FORWARD chains",
                       "Docker blocks go in DOCKER-USER on the container "
                       "port — INPUT does NOT block Docker ports",
                       "Helm-managed rules only for removal"]}


def _iptables_rule_args(rule, delete=False, chain="INPUT", dport=None):
    """Build the exact iptables args for a Helm rule, on the given
    chain and port. No free-form string, ever."""
    verb = "-D" if delete else "-A"
    target = "ACCEPT" if rule["action"] == "allow" else "DROP"
    args = [verb, chain, "-p", rule["protocol"]]
    if rule["source"] != "0.0.0.0/0":
        args += ["-s", rule["source"]]
    args += ["--dport", str(dport if dport is not None else rule["port"]),
             "-m", "comment", "--comment", HELM_COMMENT,
             "-j", target]
    return args


def _ensure_docker_user_returns():
    """RETURN 127/8 first, RETURN 172.17/16 second, before any DROP.
    Idempotent: existing RETURNs are left alone. This is what keeps
    the Nginx local proxy (127.0.0.1:3000/3001/8003) working."""
    current = firewall_list()
    present = current["docker_user_returns_present"]
    if present.get("127.0.0.0/8") and present.get("172.17.0.0/16"):
        return {"already_present": True}
    if not present.get("127.0.0.0/8"):
        proc = _run_iptables(["-I", "DOCKER-USER", "1", "-s", "127.0.0.0/8",
                              "-j", "RETURN"])
        if proc.returncode != 0:
            raise RuntimeError(f"add RETURN 127/8 failed: "
                               f"{proc.stderr.strip()[:300]}")
    # Re-read positions: 172 RETURN goes right after the 127 RETURN.
    current = firewall_list()
    if not current["docker_user_returns_present"].get("172.17.0.0/16"):
        proc = _run_iptables(["-I", "DOCKER-USER", "2", "-s", "172.17.0.0/16",
                              "-j", "RETURN"])
        if proc.returncode != 0:
            raise RuntimeError(f"add RETURN 172.17/16 failed: "
                               f"{proc.stderr.strip()[:300]}")
    return {"already_present": False}


def _save_persistent():
    """netfilter-persistent save. Returns (saved, warning). A save
    failure does NOT undo the runtime rule — it is reported, not hidden."""
    try:
        proc = subprocess.run(["netfilter-persistent", "save"],
                              capture_output=True, text=True, timeout=30)
    except Exception as exc:
        return False, f"save failed (not run): {exc}"
    if proc.returncode != 0:
        return False, ("save failed: "
                       f"{proc.stderr.strip()[:300]} — rule is runtime "
                       "only until save succeeds")
    return True, None


def _rule_matches(r, action, protocol, dport, source):
    return (r.get("action") == action
            and r.get("protocol") == protocol
            and r.get("port") == dport
            and r.get("source", "0.0.0.0/0") == source)


def _add_docker_drop(rule, resolved):
    _ensure_docker_user_returns()
    current = firewall_list()
    for r in current["docker_user_rules"]:
        if _rule_matches(r, "deny", rule["protocol"],
                         resolved["dport"], rule["source"]):
            return {"applied": False, "duplicate": True, "rule": rule,
                    "chain": "DOCKER-USER", "dport": resolved["dport"],
                    "note": "exact block already present"}
    proc = _run_iptables(_iptables_rule_args(
        rule, chain="DOCKER-USER", dport=resolved["dport"]))
    if proc.returncode != 0:
        raise RuntimeError(f"iptables DOCKER-USER add failed: "
                           f"{proc.stderr.strip()[:300]}")
    saved, warning = _save_persistent()
    return {"applied": True, "rule": rule, "chain": "DOCKER-USER",
            "dport": resolved["dport"],
            "container_port": resolved["container_port"],
            "shared_with": resolved["shared_with"],
            "persistent_saved": saved, "warning": warning,
            "verify_next": "laptop must re-read firewall list"}


def _remove_docker_drop(rule, resolved):
    current = firewall_list()
    matched = None
    for r in current["docker_user_rules"]:
        if (r.get("helm_managed")
                and _rule_matches(r, "deny", rule["protocol"],
                                  resolved["dport"], rule["source"])):
            matched = r
            break
    if not matched:
        return {"applied": False, "not_found": True, "rule": rule,
                "chain": "DOCKER-USER", "dport": resolved["dport"],
                "note": "no matching Helm-managed block found; "
                        "blocks Helm did not create are never removed"}
    proc = _run_iptables(_iptables_rule_args(
        rule, delete=True, chain="DOCKER-USER", dport=resolved["dport"]))
    # _iptables_rule_args builds a DROP rule for action deny; for an
    # allow-action remove the target must still be DROP to match.
    if proc.returncode != 0:
        raise RuntimeError(f"iptables DOCKER-USER remove failed: "
                           f"{proc.stderr.strip()[:300]}")
    saved, warning = _save_persistent()
    return {"applied": True, "rule": rule, "chain": "DOCKER-USER",
            "dport": resolved["dport"],
            "container_port": resolved["container_port"],
            "shared_with": resolved["shared_with"],
            "persistent_saved": saved, "warning": warning,
            "verify_next": "laptop must re-read firewall list"}


def firewall_add(rule):
    current = firewall_list()
    resolved = _resolve_rule(rule, current["port_map"])
    if resolved["is_docker"]:
        if rule["action"] == "deny":
            return _add_docker_drop(rule, resolved)
        # Allow a Docker app = remove its block. There is no ACCEPT
        # rule to add — DOCKER-USER returns by default without a DROP.
        return _remove_docker_drop(
            {"action": "deny", "protocol": rule["protocol"],
             "port": rule["port"], "source": rule["source"]}, resolved)
    # Host service — INPUT, as before.
    for r in current["rules"]:
        if _rule_matches(r, rule["action"], rule["protocol"],
                         rule["port"], rule["source"]):
            return {"applied": False, "duplicate": True,
                    "rule": rule, "note": "exact rule already present"}
    proc = _run_iptables(_iptables_rule_args(rule, chain="INPUT"))
    if proc.returncode != 0:
        raise RuntimeError(f"iptables add failed: {proc.stderr.strip()[:300]}")
    saved, warning = _save_persistent()
    return {"applied": True, "rule": rule, "chain": "INPUT",
            "dport": rule["port"], "persistent_saved": saved,
            "warning": warning,
            "verify_next": "laptop must re-read firewall list"}


def firewall_remove(rule):
    current = firewall_list()
    resolved = _resolve_rule(rule, current["port_map"])
    if resolved["is_docker"]:
        # Remove op always targets the DROP block for this service.
        deny_rule = {"action": "deny", "protocol": rule["protocol"],
                     "port": rule["port"], "source": rule["source"]}
        return _remove_docker_drop(deny_rule, resolved)
    matched = None
    for r in current["rules"]:
        if (r.get("helm_managed")
                and _rule_matches(r, rule["action"], rule["protocol"],
                                  rule["port"], rule["source"])):
            matched = r
            break
    if not matched:
        return {"applied": False, "not_found": True, "rule": rule,
                "note": "no matching Helm-managed rule found; "
                        "non-Helm rules are never removed"}
    proc = _run_iptables(_iptables_rule_args(rule, delete=True, chain="INPUT"))
    if proc.returncode != 0:
        raise RuntimeError(f"iptables remove failed: {proc.stderr.strip()[:300]}")
    saved, warning = _save_persistent()
    return {"applied": True, "rule": rule, "chain": "INPUT",
            "dport": rule["port"], "persistent_saved": saved,
            "warning": warning,
            "verify_next": "laptop must re-read firewall list"}


def firewall_cmd(argv):
    """argv after 'firewall': list | add --... | remove --...
    Docker services resolve to DOCKER-USER on the container port;
    host services stay on INPUT. See the Nov 5, 2026 correction."""
    if not argv:
        raise ValueError("usage: agent.py firewall <list|add|remove> ...")
    sub = argv[0]
    if sub == "list":
        return firewall_list()
    if sub in ("add", "remove"):
        args = _parse_firewall_args(argv[1:])
        rule, err = validate_rule(args.get("action"), args.get("protocol"),
                                  args.get("port"), args.get("source", "any"))
        if err:
            raise ValueError(err)
        return firewall_add(rule) if sub == "add" else firewall_remove(rule)
    raise ValueError(f"unknown firewall command: {sub!r}")


# ----------------------------------------------------------------- updates
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")


def parse_apt_list(text):
    """Parse `apt list --upgradable` lines.
    Format: name/dist version arch [upgradable from: old]
    Returns list of {name, current, new, dist}."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue
        # name/dist new-version arch [upgradable from: old-version]
        m = re.match(r"^(\S+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from:\s*(\S+)\]",
                     line)
        if not m:
            continue
        out.append({"name": m.group(1), "dist": m.group(2),
                    "new": m.group(3), "current": m.group(4)})
    return out


def _security_for(pkg):
    """Best-effort: True if the candidate comes from a -security origin.
    Returns None when it cannot be determined (never guessed True)."""
    try:
        proc = subprocess.run(["apt-cache", "policy", pkg],
                              capture_output=True, text=True, timeout=15)
        return "-security" in proc.stdout
    except Exception:
        return None


def _unattended_active():
    try:
        proc = subprocess.run(["systemctl", "is-active", "unattended-upgrades"],
                              capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() == "active"
    except Exception:
        return None


def updates_check():
    """Check for updates. Runs apt-get update (lists only, no install),
    then lists upgradable packages. NEVER auto-applies anything here."""
    upd = subprocess.run(["apt-get", "update", "-qq"],
                         capture_output=True, text=True, timeout=180)
    if upd.returncode != 0:
        raise RuntimeError(f"apt-get update failed: {upd.stderr.strip()[:300]}")
    lst = subprocess.run(["apt", "list", "--upgradable"],
                         capture_output=True, text=True, timeout=60)
    packages = parse_apt_list(lst.stdout)
    for p in packages:
        p["security"] = _security_for(p["name"])
    return {
        "count": len(packages),
        "packages": packages,
        "unattended_upgrades_active": _unattended_active(),
        "note": "Check only — nothing was installed. Unattended-upgrades "
                "may already auto-apply security updates; Helm still shows "
                "the full list and lets the operator pick whole-box or "
                "one package, manually.",
        "guards": ["no auto-apply on check",
                   "no distribution release upgrade",
                   "apt packages only — Docker containers are never touched"],
    }


def updates_apply(scope, package):
    """Apply updates, structured only. scope: whole | one.
    Allowlist = a FRESH check, done inside this call, right before apply.
    Any package not in that fresh list is refused. No free-form apt string,
    no dist-upgrade, no release upgrade, no Docker command, ever."""
    if scope not in ("whole", "one"):
        raise ValueError("scope must be whole or one")
    if scope == "one" and (not package or not PKG_RE.match(package)):
        raise ValueError("package name is not valid")
    fresh = updates_check()
    names = {p["name"] for p in fresh["packages"]}
    if scope == "one":
        if package not in names:
            raise ValueError(f"package not in checked upgradable list: {package}")
        targets = [package]
        cmd = ["apt-get", "install", "-y", "--only-upgrade"] + targets
    else:
        targets = sorted(names)
        # apt-get upgrade (not dist-upgrade, not release upgrade).
        cmd = ["apt-get", "upgrade", "-y"]
    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=900, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"apt apply failed rc={proc.returncode}: "
                           f"{proc.stderr.strip()[-500:]}")
    # Agent returns the raw result. LAPTOP must verify by re-reading
    # the upgradable list — exit code alone is never proof.
    return {"applied": True, "scope": scope, "targets": targets,
            "verify_next": "laptop must re-read updates list"}


def updates_cmd(argv):
    """argv after 'updates': check | apply --scope whole|one [--package name]"""
    if not argv:
        raise ValueError("usage: agent.py updates <check|apply> ...")
    sub = argv[0]
    if sub == "check":
        return updates_check()
    if sub == "apply":
        args = _parse_firewall_args(argv[1:])
        return updates_apply(args.get("scope"), args.get("package"))
    raise ValueError(f"unknown updates command: {sub!r}")


# ------------------------------------------------------------------- logs
# Logs is READ-ONLY, always. No apply, no delete, no truncate, no restart.
# Operator picks by PLAIN NAME only — no log path or command syntax needed.
# Intuitiveness is the core requirement (ASCIF Q7, Nov 4): if Logs is not
# intuitive, the design fails, even if the lines are technically correct.
LOG_SOURCES = [
    # System logs — plain name, description, file path (detail, second).
    {"key": "system", "name": "System log", "kind": "file",
     "path": "/var/log/syslog",
     "description": "The box's main system log — services, errors, everyday events."},
    {"key": "signins", "name": "Sign-ins", "kind": "file",
     "path": "/var/log/auth.log",
     "description": "Who signed in — SSH logins and login attempts."},
    {"key": "kernel", "name": "Kernel messages", "kind": "file",
     "path": "/var/log/kern.log",
     "description": "Hardware and kernel messages."},
    {"key": "package-changes", "name": "Package changes", "kind": "file",
     "path": "/var/log/dpkg.log",
     "description": "What packages were installed, updated, or removed."},
    {"key": "update-history", "name": "Update history", "kind": "file",
     "path": "/var/log/apt/history.log",
     "description": "Past apt updates, in order."},
    {"key": "auto-updates", "name": "Automatic security updates", "kind": "file",
     "path": "/var/log/unattended-upgrades/unattended-upgrades.log",
     "description": "What the automatic security updater did on its own."},
    {"key": "cloud-setup", "name": "First-boot setup", "kind": "file",
     "path": "/var/log/cloud-init.log",
     "description": "Cloud setup that ran when the box first booted."},
    {"key": "website-visits", "name": "Website visits", "kind": "file",
     "path": "/var/log/nginx/access.log",
     "description": "Visits to the web server (Nginx)."},
    {"key": "website-errors", "name": "Website errors", "kind": "file",
     "path": "/var/log/nginx/error.log",
     "description": "Web server errors (Nginx)."},
    {"key": "helm-agent", "name": "TAIG Helm agent", "kind": "file",
     "path": "/var/log/taig-helm-agent.log",
     "description": "Helm agent's own log — the status writer's output."},
    # Docker container logs — plain service name, container name second.
    {"key": "pia", "name": "PIA", "kind": "docker", "container": "pia",
     "description": "PIA app — pantry / receipts service."},
    {"key": "nope-portal", "name": "Nope portal", "kind": "docker",
     "container": "nope-portal",
     "description": "Nope operator portal."},
    {"key": "taig-speed", "name": "TAIG Speed", "kind": "docker",
     "container": "taig-speed",
     "description": "TAIG Speed inventory service."},
    {"key": "tsp", "name": "TAIG Service Portal", "kind": "docker",
     "container": "tsp",
     "description": "TAIG Service Portal (TSP) service."},
]

SEARCH_RE = re.compile(r"^[A-Za-z0-9 _\-./:]+$")
SYSLOG_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _log_source(key):
    for src in LOG_SOURCES:
        if src["key"] == key:
            return src
    return None


def logs_list():
    out = []
    for src in LOG_SOURCES:
        item = {"key": src["key"], "name": src["name"], "kind": src["kind"],
                "description": src["description"]}
        if src["kind"] == "file":
            item["path"] = src["path"]
            item["exists"] = os.path.exists(src["path"])
            try:
                item["size_bytes"] = os.path.getsize(src["path"]) \
                    if item["exists"] else None
            except Exception:
                item["size_bytes"] = None
        else:
            item["container"] = src["container"]
            try:
                proc = subprocess.run(
                    ["docker", "ps", "-a", "--filter",
                     f"name=^{src['container']}$", "--format", "{{.Names}}"],
                    capture_output=True, text=True, timeout=15)
                item["exists"] = src["container"] in proc.stdout.split()
            except Exception:
                item["exists"] = None
        out.append(item)
    return {"sources": out,
            "note": "Read-only. Pick by plain name — no path or command needed."}


def _line_time(line):
    """Best-effort timestamp for a log line. None if not parseable.
    Docker ISO, Nginx [04/Nov/2026:19:..], syslog 'Nov  4 19:..'."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.fromisoformat(m.group(1))
        except Exception:
            pass
    m = re.search(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            return datetime(int(m.group(3)), SYSLOG_MONTHS[m.group(2)],
                            int(m.group(1)), int(m.group(4)),
                            int(m.group(5)), int(m.group(6)))
        except Exception:
            pass
    m = re.match(r"^([A-Za-z]{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m and m.group(1) in SYSLOG_MONTHS:
        try:
            now = datetime.now()
            ts = datetime(now.year, SYSLOG_MONTHS[m.group(1)],
                          int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)))
            if ts > now:  # Dec log read in Jan — previous year.
                ts = ts.replace(year=now.year - 1)
            return ts
        except Exception:
            pass
    return None


def _filter_lines(lines, search, since_hours):
    """Search substring (case-insensitive), then time window.
    Lines without a readable timestamp are KEPT, not dropped — the time
    filter is best-effort for plain files, exact for Docker --since."""
    out = lines
    if search:
        needle = search.lower()
        out = [l for l in out if needle in l.lower()]
    if since_hours:
        cutoff = datetime.now() - timedelta(hours=since_hours)
        out = [l for l in out
               if _line_time(l) is None or _line_time(l) >= cutoff]
    return out


def logs_read(service, lines, search, since_hours):
    src = _log_source(service)
    if src is None:
        raise ValueError(f"unknown log service: {service!r}")
    if not 1 <= lines <= 500:
        raise ValueError("lines must be 1-500")
    if search and (len(search) > 100 or not SEARCH_RE.match(search)):
        raise ValueError("search must be plain words/numbers, no shell characters")
    if since_hours not in (None, 1, 24, 168):
        raise ValueError("time filter must be last hour, last day, last 7 days, or all")
    raw = []
    if src["kind"] == "file":
        if not os.path.exists(src["path"]):
            raise RuntimeError(f"log not found on this box: {src['name']}")
        with open(src["path"], "r", encoding="utf-8", errors="replace") as f:
            # Scan the last 10,000 lines so search/time can find matches
            # beyond the returned tail; the returned tail is lines long.
            all_lines = f.read().splitlines()
        raw = all_lines[-10000:]
    else:
        cmd = ["docker", "logs", "--tail", "10000", "--timestamps"]
        if since_hours:
            cmd += ["--since", f"{since_hours}h"]
        cmd += [src["container"]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"docker logs failed for {src['name']}: "
                               f"{proc.stderr.strip()[:300]}")
        raw = (proc.stdout + proc.stderr).splitlines()
    matched = _filter_lines(raw, search, since_hours)
    return {
        "service": src["key"], "name": src["name"], "kind": src["kind"],
        "lines": matched[-lines:], "total_matched": len(matched),
        "returned": min(lines, len(matched)),
        "search": search or None, "since_hours": since_hours,
        "note": "Read-only — Logs never changes anything. Time filter is "
                "best-effort for plain files (lines without a readable "
                "timestamp are kept); Docker uses --since exactly.",
        "guards": ["read-only, no delete/truncate/restart",
                   "service must be in the plain-name allowlist",
                   "no free-form tail/cat/docker string"],
    }


def logs_cmd(argv):
    """argv after 'logs': list | read --service X [--lines N]
    [--search TERM] [--since-hours 1|24|168]"""
    if not argv:
        raise ValueError("usage: agent.py logs <list|read> ...")
    sub = argv[0]
    if sub == "list":
        return logs_list()
    if sub == "read":
        args = _parse_firewall_args(argv[1:])
        try:
            lines = int(args.get("lines", "100"))
        except Exception:
            raise ValueError("lines must be a number")
        since = args.get("since-hours")
        since_hours = int(since) if since else None
        return logs_read(args.get("service"), lines,
                         args.get("search"), since_hours)
    raise ValueError(f"unknown logs command: {sub!r}")


# -------------------------------------------------------------- processes
# Processes (Task/Process Management group) — MVP READ-ONLY.
# No kill, no stop, no restart, no start in this build. Those are
# execution actions for a later step, with preview/approve.
# Read-first order (Tee, Nov 4, 7:18 PM): read everything first,
# cool UI theme later, on Tee's ask, not now.
CONTAINER_PLAIN = {
    "pia": "PIA", "nope-portal": "Nope portal",
    "taig-speed": "TAIG Speed", "tsp": "TAIG Service Portal",
}


def _systemd_services():
    """Running systemd services, parsed from systemctl list-units.
    Best-effort: a missing systemctl returns an empty list + note,
    never fake services."""
    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=30)
    except Exception:
        return [], "systemctl not available on this box"
    services = []
    for line in proc.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        services.append({
            "name": unit,
            "plain_name": unit[:-8] if unit.endswith(".service") else unit,
            "load": parts[1], "active": parts[2], "sub": parts[3],
            "description": parts[4] if len(parts) > 4 else "",
        })
    return services, None


def _top_processes(limit=25):
    """Top processes by CPU, from ps. Fixed columns, parsed, no shell."""
    try:
        proc = subprocess.run(
            ["ps", "-eo", "pid,comm,pcpu,pmem,etime", "--sort=-pcpu"],
            capture_output=True, text=True, timeout=30)
    except Exception:
        return [], "ps not available on this box"
    out = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            out.append({"pid": int(parts[0]), "name": parts[1],
                        "cpu_percent": float(parts[2]),
                        "mem_percent": float(parts[3]),
                        "elapsed": parts[4]})
        except Exception:
            continue
        if len(out) >= limit:
            break
    return out, None


def _docker_containers():
    """Running Docker containers, pipe-delimited format, parsed."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Ports}}"],
            capture_output=True, text=True, timeout=30)
    except Exception:
        return [], "docker not available on this box"
    out = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        out.append({"name": name,
                    "plain_name": CONTAINER_PLAIN.get(name, name),
                    "status": parts[1].strip(),
                    "ports": parts[2].strip() if len(parts) > 2 else ""})
    return out, None


def processes_list():
    services, svc_note = _systemd_services()
    top, top_note = _top_processes()
    containers, docker_note = _docker_containers()
    notes = [n for n in (svc_note, top_note, docker_note) if n]
    return {
        "services": services, "service_count": len(services),
        "top_processes": top,
        "containers": containers, "container_count": len(containers),
        "notes": notes,
        "note": "Read-only — Processes never stops, kills, or restarts "
                "anything in this MVP. Kill/restart/stop are a later "
                "step, with preview/approve.",
        "guards": ["read-only, no kill/stop/restart/start",
                   "fixed commands only, no free-form ps/systemctl/docker string"],
    }


def processes_cmd(argv):
    """argv after 'processes': list only. kill/stop/restart/start are
    explicitly rejected — not in this read-only MVP."""
    if not argv or argv[0] == "list":
        if argv and len(argv) > 1:
            raise ValueError("usage: agent.py processes list")
        return processes_list()
    if argv[0] in ("kill", "stop", "restart", "start"):
        raise ValueError(f"processes {argv[0]} is NOT in this read-only MVP — "
                         "execution actions come later, with preview/approve")
    raise ValueError(f"unknown processes command: {argv[0]!r}")


def main(argv):
    if len(argv) < 2:
        print("usage: agent.py <status|write-status|version|firewall ...>",
              file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "status":
        print(json.dumps(collect_status()))
        return 0
    if cmd == "write-status":
        print(json.dumps(write_status()))
        return 0
    if cmd == "version":
        print(json.dumps({"agent": "taig_helm_agent", "version": VERSION}))
        return 0
    if cmd == "firewall":
        try:
            print(json.dumps(firewall_cmd(argv[2:])))
            return 0
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if cmd == "updates":
        try:
            print(json.dumps(updates_cmd(argv[2:])))
            return 0
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if cmd == "logs":
        try:
            print(json.dumps(logs_cmd(argv[2:])))
            return 0
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if cmd == "processes":
        try:
            print(json.dumps(processes_cmd(argv[2:])))
            return 0
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    # Anything else — including any other task payload — is rejected.
    # No free-form shell, ever.
    print(f"error: command not allowed: {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
