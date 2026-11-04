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

Verification lives on the laptop, not here: the laptop must NOT trust
exit code alone. It verifies a change by re-reading box state.
"""

import json
import os
import platform
import shutil
import socket
import sys
import time
from datetime import datetime, timezone

VERSION = "0.1.0"
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


def main(argv):
    if len(argv) != 2:
        print("usage: agent.py <status|write-status|version>", file=sys.stderr)
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
    # Anything else — including any future task payload — is rejected.
    # v1 proof has no task execution. No free-form shell, ever.
    print(f"error: command not allowed in v1 proof: {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
