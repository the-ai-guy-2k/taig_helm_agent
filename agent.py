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
from datetime import datetime, timezone

VERSION = "0.2.0"
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


def _parse_iptables_save(text):
    """Parse `iptables -S INPUT` lines into structured rules."""
    rules = []
    policies = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("-P INPUT "):
            policies["INPUT"] = line.split()[2]
        elif line.startswith("-A INPUT "):
            rule = {"chain": "INPUT", "raw": line, "helm_managed": False}
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
            if HELM_COMMENT in line:
                rule["helm_managed"] = True
            rules.append(rule)
    return policies, rules


def firewall_list():
    proc = _run_iptables(["-S", "INPUT"])
    if proc.returncode != 0:
        raise RuntimeError(f"iptables -S INPUT failed: {proc.stderr.strip()[:300]}")
    policies, rules = _parse_iptables_save(proc.stdout)
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
            "listening_ports": listening,
            "persistent_note": "Runtime rules only. iptables-persistent NOT "
                               "installed — persistence is an open decision "
                               "in main chat. Rules do NOT survive reboot "
                               "until that decision is made.",
            "guards": ["never deny SSH port 22",
                       "never touch DOCKER chains",
                       "INPUT chain only, Helm-managed rules only for removal"]}


def _iptables_rule_args(rule, delete=False):
    """Build the exact iptables args for a Helm rule. INPUT only."""
    verb = "-D" if delete else "-A"
    target = "ACCEPT" if rule["action"] == "allow" else "DROP"
    args = [verb, "INPUT", "-p", rule["protocol"]]
    if rule["source"] != "0.0.0.0/0":
        args += ["-s", rule["source"]]
    args += ["--dport", str(rule["port"]),
             "-m", "comment", "--comment", HELM_COMMENT,
             "-j", target]
    return args


def firewall_add(rule):
    # Duplicate check first: re-read, refuse an exact duplicate.
    current = firewall_list()
    for r in current["rules"]:
        if (r.get("action") == rule["action"]
                and r.get("protocol") == rule["protocol"]
                and r.get("port") == rule["port"]
                and r.get("source", "0.0.0.0/0") == rule["source"]):
            return {"applied": False, "duplicate": True,
                    "rule": rule, "note": "exact rule already present"}
    proc = _run_iptables(_iptables_rule_args(rule))
    if proc.returncode != 0:
        raise RuntimeError(f"iptables add failed: {proc.stderr.strip()[:300]}")
    # Agent returns the raw result. LAPTOP must verify by re-reading rules.
    return {"applied": True, "rule": rule,
            "verify_next": "laptop must re-read firewall list"}


def firewall_remove(rule):
    # Removal only for a Helm-managed rule, matched exactly.
    current = firewall_list()
    matched = None
    for r in current["rules"]:
        if (r.get("helm_managed")
                and r.get("action") == rule["action"]
                and r.get("protocol") == rule["protocol"]
                and r.get("port") == rule["port"]
                and r.get("source", "0.0.0.0/0") == rule["source"]):
            matched = r
            break
    if not matched:
        return {"applied": False, "not_found": True, "rule": rule,
                "note": "no matching Helm-managed rule found; "
                        "non-Helm rules are never removed"}
    proc = _run_iptables(_iptables_rule_args(rule, delete=True))
    if proc.returncode != 0:
        raise RuntimeError(f"iptables remove failed: {proc.stderr.strip()[:300]}")
    return {"applied": True, "rule": rule,
            "verify_next": "laptop must re-read firewall list"}


def firewall_cmd(argv):
    """argv after 'firewall': list | add --... | remove --..."""
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
    # Anything else — including any other task payload — is rejected.
    # No free-form shell, ever.
    print(f"error: command not allowed: {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
