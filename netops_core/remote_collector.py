"""Self-contained Linux collector sent to an authorized host over SSH."""

REMOTE_COLLECTOR = r'''
import json
import os
import platform
import shutil
import socket
import subprocess
import time

MAX_CHARS = 64000

def run(args, timeout=8):
    if not shutil.which(args[0]):
        return {"available": False, "returncode": None, "stdout": "", "stderr": "not found"}
    started = time.monotonic()
    try:
        proc = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
        return {
            "available": True,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-MAX_CHARS:],
            "stderr": proc.stderr[-MAX_CHARS:],
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "returncode": None,
            "stdout": "",
            "stderr": "timed out",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

commands = {
    "addresses": ["ip", "-j", "address"],
    "routes": ["ip", "-j", "route", "show", "table", "all"],
    "rules": ["ip", "-j", "rule"],
    "listeners": ["ss", "-H", "-lntup"],
    "services": ["systemctl", "--no-pager", "--plain", "list-units", "--type=service", "--state=running"],
    "failed_services": ["systemctl", "--no-pager", "--plain", "--failed"],
    "dns": ["resolvectl", "status"],
    "firewall_nft": ["nft", "list", "ruleset"],
    "firewall_ufw": ["ufw", "status", "verbose"],
    "congestion_control": ["sysctl", "net.ipv4.tcp_congestion_control"],
    "qdisc": ["sysctl", "net.core.default_qdisc"],
}

results = {name: run(command) for name, command in commands.items()}
versions = {}
for name, candidates in {
    "x-ui": [["x-ui", "version"], ["/usr/local/x-ui/x-ui", "version"]],
    "xray": [["xray", "version"], ["/usr/local/x-ui/bin/xray-linux-amd64", "version"], ["/usr/local/x-ui/bin/xray-linux-arm64", "version"]],
}.items():
    for command in candidates:
        if os.path.isfile(command[0]) or shutil.which(command[0]):
            versions[name] = run(command)
            break

files = {}
for path in ["/etc/x-ui/x-ui.db", "/usr/local/x-ui/bin/config.json", "/etc/xray/config.json"]:
    try:
        stat = os.stat(path)
        files[path] = {"exists": True, "size": stat.st_size, "mode": oct(stat.st_mode & 0o777)}
    except OSError:
        files[path] = {"exists": False}

try:
    loadavg = os.getloadavg()
except OSError:
    loadavg = None

payload = {
    "platform": {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
    },
    "resources": {
        "loadavg": loadavg,
        "cpu_count": os.cpu_count(),
        "disk_root": shutil.disk_usage("/")._asdict(),
    },
    "commands": results,
    "versions": versions,
    "files": files,
}
print(json.dumps(payload, ensure_ascii=False))
'''
