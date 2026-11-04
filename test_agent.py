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
