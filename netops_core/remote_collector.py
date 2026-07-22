"""Self-contained Linux collector sent to an authorized host over SSH."""

REMOTE_COLLECTOR = r'''
import json
import os
import platform
import re
import selectors
import signal
import shutil
import socket
import subprocess
import time
import unicodedata

# There are at most 13 command results and two captured streams per result.
# After control cleanup, each retained character needs at most four UTF-8
# bytes in the emitted JSON.  Thus 13 * 2 * 8,000 * 4 = 832,000 bytes, leaving
# room for fixed metadata below the caller's 1 MiB capture ceiling.
MAX_CHARS = 8000
MAX_STREAM_BYTES = MAX_CHARS * 4
READ_CHUNK_BYTES = 65536
TERMINATION_GRACE_SECONDS = 0.5
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SYSTEM_ENVIRONMENT = {"PATH": SYSTEM_PATH, "LC_ALL": "C"}
ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\|$)|"
    r"[PX^_][^\x1b]*(?:\x1b\\|$)|[@-_])"
)

def clean(value):
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = ANSI_ESCAPE_RE.sub("", text)
    return "".join(
        character
        if character in {"\n", "\t"}
        or (
            unicodedata.category(character) not in {"Cc", "Cf"}
            and character not in {"\u2028", "\u2029"}
        )
        else " "
        for character in text
    )[-MAX_CHARS:]

def append_tail(buffer, chunk):
    if len(chunk) >= MAX_STREAM_BYTES:
        buffer[:] = chunk[-MAX_STREAM_BYTES:]
        return
    overflow = len(buffer) + len(chunk) - MAX_STREAM_BYTES
    if overflow > 0:
        del buffer[:overflow]
    buffer.extend(chunk)

def process_group_exists(process_group_id):
    if os.name != "posix":
        return False
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def terminate_process_group(proc):
    if os.name != "posix":
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=TERMINATION_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=TERMINATION_GRACE_SECONDS)
        return

    process_group_id = proc.pid
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while process_group_exists(process_group_id) and time.monotonic() < deadline:
        # Reap an exited group leader so a leader-only group is not mistaken
        # for live background work on platforms that report zombies to killpg.
        proc.poll()
        time.sleep(0.02)
    if process_group_exists(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=TERMINATION_GRACE_SECONDS)

def close_registered_stream(selector, stream):
    try:
        selector.unregister(stream)
    except (KeyError, ValueError):
        pass
    stream.close()

def drain_ready_streams(selector, buffers, wait_seconds):
    events = selector.select(wait_seconds)
    for key, _mask in events:
        stream = key.fileobj
        try:
            chunk = os.read(stream.fileno(), READ_CHUNK_BYTES)
        except OSError:
            chunk = b""
        if chunk:
            append_tail(buffers[key.data], chunk)
        else:
            close_registered_stream(selector, stream)
    return bool(events)

def run(args, timeout=8):
    executable = shutil.which(args[0], path=SYSTEM_PATH)
    if not executable:
        return {"available": False, "returncode": None, "stdout": "", "stderr": "not found"}
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            [executable, *args[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
            env=SYSTEM_ENVIRONMENT,
        )
    except OSError as exc:
        return {
            "available": False,
            "returncode": None,
            "stdout": "",
            "stderr": clean(str(exc)),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    assert proc.stdout is not None
    assert proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = started + max(float(timeout), 0.0)
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            drain_ready_streams(selector, buffers, min(remaining, 0.1))

        if not timed_out:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
            else:
                try:
                    returncode = proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True

        if timed_out:
            terminate_process_group(proc)
            drain_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
            while selector.get_map() and time.monotonic() < drain_deadline:
                drain_ready_streams(
                    selector,
                    buffers,
                    min(0.05, max(drain_deadline - time.monotonic(), 0.0)),
                )
        else:
            # Kill background work that remains in this command's process
            # group even if it closed both pipes. A deliberately detached new
            # session is outside this process-group boundary.
            if process_group_exists(proc.pid):
                terminate_process_group(proc)
    finally:
        for key in list(selector.get_map().values()):
            close_registered_stream(selector, key.fileobj)
        selector.close()

    stdout = clean(bytes(buffers["stdout"]).decode("utf-8", errors="replace"))
    stderr = clean(bytes(buffers["stderr"]).decode("utf-8", errors="replace"))
    if timed_out:
        stderr = clean((stderr + "\n" if stderr else "") + "timed out")
        returncode = None
    return {
        "available": True,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
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

def main():
    results = {name: run(command) for name, command in commands.items()}
    versions = {}
    for name, candidates in {
        "x-ui": [["x-ui", "version"], ["/usr/local/x-ui/x-ui", "version"]],
        "xray": [["xray", "version"], ["/usr/local/x-ui/bin/xray-linux-amd64", "version"], ["/usr/local/x-ui/bin/xray-linux-arm64", "version"]],
    }.items():
        for command in candidates:
            if os.path.isfile(command[0]) or shutil.which(command[0], path=SYSTEM_PATH):
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

if __name__ == "__main__":
    main()
'''
