#!/usr/bin/env python3
"""Local shape test for agent.py. Run: python3 test_agent.py"""
import json
import subprocess
import sys

out = subprocess.run([sys.executable, "agent.py", "status"],
                     capture_output=True, text=True, check=True)
data = json.loads(out.stdout)
assert data["agent"] == "taig_helm_agent"
assert data["version"]
# Firewall guards must fail BEFORE touching iptables.
for args in (["firewall", "add", "--action", "deny", "--protocol", "tcp",
              "--port", "22", "--source", "any"],
             ["firewall", "add", "--action", "allow", "--protocol", "tcp",
              "--port", "99999", "--source", "any"],
             ["firewall", "add", "--action", "allow", "--protocol", "tcp",
              "--port", "80", "--source", "not-an-ip"]):
    bad = subprocess.run([sys.executable, "agent.py"] + args,
                         capture_output=True, text=True)
    assert bad.returncode != 0, f"guard failed for {args}: {bad.stdout}"
print("firewall guards OK: deny-22, bad-port, bad-source all rejected")
# Firewall DOCKER-USER correction (Nov 5): host -> container mapping.
from agent import _parse_iptables_save, _resolve_rule, KNOWN_PORT_MAP  # noqa: E402
_, du = _parse_iptables_save(
    "-A DOCKER-USER -s 127.0.0.0/8 -j RETURN\n"
    "-A DOCKER-USER -s 172.17.0.0/16 -j RETURN\n"
    "-A DOCKER-USER -p tcp --dport 3000 -m comment --comment taig-helm -j DROP\n"
    "-A DOCKER-USER -p tcp --dport 8000 -j DROP\n", "DOCKER-USER")
assert [r["action"] for r in du] == ["return", "return", "deny", "deny"]
assert du[2]["helm_managed"] is True and du[3]["helm_managed"] is False
r = _resolve_rule({"action": "deny", "protocol": "tcp", "port": 8003,
                   "source": "0.0.0.0/0"}, KNOWN_PORT_MAP)
assert r["chain"] == "DOCKER-USER" and r["dport"] == 8000 and r["service"] == "PIA"
r = _resolve_rule({"action": "deny", "protocol": "tcp", "port": 3001,
                   "source": "0.0.0.0/0"}, KNOWN_PORT_MAP)
assert r["chain"] == "DOCKER-USER" and r["dport"] == 3000
assert r["shared_with"] == ["Nope portal", "TAIG Speed"]
r = _resolve_rule({"action": "deny", "protocol": "tcp", "port": 80,
                   "source": "0.0.0.0/0"}, KNOWN_PORT_MAP)
assert r["chain"] == "INPUT" and r["dport"] == 80 and not r["is_docker"]
print("firewall mapping OK: 8003->8000, 3001->3000 shared, 80 stays INPUT")
# Updates parsing + guards: no live apt apply in this test.
sys.path.insert(0, ".")
from agent import parse_apt_list, updates_cmd  # noqa: E402
sample = ("Listing...\n"
          "apt/noble-updates 2.8.4ubuntu0.1 amd64 [upgradable from: 2.8.3]\n"
          "tmux/noble-updates 3.3a-1ubuntu0.1 amd64 [upgradable from: 3.3a-1]\n")
parsed = parse_apt_list(sample)
assert [p["name"] for p in parsed] == ["apt", "tmux"]
assert parsed[0]["current"] == "2.8.3" and parsed[0]["new"] == "2.8.4ubuntu0.1"
for bad in (["updates", "dist-upgrade"],
            ["updates", "apply", "--scope", "bogus"],
            ["updates", "apply", "--scope", "one", "--package", "rm -rf /"]):
    try:
        updates_cmd(bad[1:])
        raise AssertionError(f"updates guard failed for {bad}")
    except Exception:
        pass
print("updates guards OK: parse, dist-upgrade rejected, bad scope/package rejected")
# Logs: allowlist + read-only guards, no live Docker/file read in this test.
from agent import logs_list, logs_cmd, _line_time  # noqa: E402
keys = [s["key"] for s in logs_list()["sources"]]
assert "system" in keys and "pia" in keys and "tsp" in keys
assert _line_time("Nov  4 19:17:37 host sshd[1]: ok") is not None
assert _line_time("2026-11-04T19:17:37.123456Z app started") is not None
for bad in (["read", "--service", "not-a-log"],
            ["read", "--service", "system", "--lines", "9999"],
            ["read", "--service", "system", "--search", "x; rm -rf /"]):
    try:
        logs_cmd(bad)
        raise AssertionError(f"logs guard failed for {bad}")
    except Exception:
        pass
print("logs guards OK: allowlist, lines cap, shell-char search rejected")
# Processes: read-only MVP — kill/stop/restart/start must be rejected,
# list must return the three sections (values are this box's, not Droplet's).
from agent import processes_cmd  # noqa: E402
for bad in (["kill", "--pid", "1"], ["stop", "--service", "nginx"],
            ["restart", "--service", "nginx"], ["bogus"]):
    try:
        processes_cmd(bad)
        raise AssertionError(f"processes guard failed for {bad}")
    except Exception:
        pass
plist = processes_cmd(["list"])
assert "services" in plist and "top_processes" in plist and "containers" in plist
print("processes guards OK: kill/stop/restart rejected, list sections present")
assert data["hostname"]
assert 0 <= (data["cpu_percent"] or 0) <= 100
assert data["memory"]["total"] and 0 <= data["memory"]["percent"] <= 100
assert data["storage"]["total"] and 0 <= data["storage"]["percent"] <= 100
assert data["disks"]
# Task execution must NOT exist in v1.
bad = subprocess.run([sys.executable, "agent.py", "task"],
                     capture_output=True, text=True)
assert bad.returncode != 0, "task must fail in v1 proof"
print("agent v1 shape OK:", data["hostname"], data["cpu_percent"],
      data["memory"]["percent"], data["storage"]["percent"])
