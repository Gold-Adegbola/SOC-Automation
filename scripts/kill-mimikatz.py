import sys, json, subprocess, datetime, os, re

LOG = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# Safety net: never kill these, even if a rule misfires.
# Matched by FULL PATH, not file name, so malware cannot hide by being
# named lsass.exe or MsMpEng.exe in some other folder.
PROTECTED_PATHS = {os.path.normcase(p) for p in (
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\smss.exe",
    r"C:\Windows\Sysmon64.exe",
    r"C:\Windows\Sysmon.exe",
    r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
)}

# Whole folders that are protected. The trailing backslash matters: it stops
# a look-alike folder such as "Windows Defender Evil" from matching.
PROTECTED_PREFIXES = tuple(os.path.normcase(p) + "\\" for p in (
    r"C:\ProgramData\Microsoft\Windows Defender",
    r"C:\Program Files\Windows Defender",
))


def norm(p):
    # Wazuh stores Windows paths in alerts with doubled backslashes
    # (C:\\Users\\Urgly\\...). Collapse any run of backslashes to one so the
    # alert path and the live path compare equal.
    return os.path.normcase(re.sub(r"\\+", r"\\", p))


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.datetime.now():%Y/%m/%d %H:%M:%S} kill-mimikatz: {msg}\n")


def inspect_pid(pid):
    ps = (
        "$p = Get-CimInstance Win32_Process -Filter 'ProcessId=" + pid + "'; "
        "if (-not $p -or -not $p.ExecutablePath) { exit 2 }; "
        "$f = $p.ExecutablePath; "
        "[pscustomobject]@{ "
        "Path = $f; "
        "Original = (Get-Item -LiteralPath $f).VersionInfo.OriginalFilename; "
        "Sha256 = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash "
        "} | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        log(f"PowerShell inspection of PID {pid} timed out or failed to start")
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        info = json.loads(r.stdout)
    except ValueError:
        return None
    return {
        "path": info.get("Path") or "",
        "original": info.get("Original") or "",
        "sha256": (info.get("Sha256") or "").upper(),
    }


def main():
    try:
        data = json.loads(sys.stdin.readline())
    except ValueError:
        log("invalid JSON input")
        sys.exit(1)

    if data.get("command") != "add":
        sys.exit(0)

    try:
        ev = data["parameters"]["alert"]["data"]["win"]["eventdata"]
        # Event 10 (process access) vs Event 1 (process create)
        if "sourceProcessId" in ev:
            pid = str(ev["sourceProcessId"])
            alert_image = ev["sourceImage"]
        else:
            pid = str(ev["processId"])
            alert_image = ev["image"]
    except KeyError:
        log("alert missing process fields")
        sys.exit(1)

    # Strict check: isdigit() alone also accepts some non-ASCII digits, and
    # the PID is placed inside a PowerShell command string.
    if not (pid.isascii() and pid.isdigit()):
        log("processId is not a plain number, refusing")
        sys.exit(1)

    live = inspect_pid(pid)
    if live is None:
        log(f"PID {pid} not running or could not be inspected, not killing")
        sys.exit(0)

    # Identity check: is this still the process the alert described?
    if norm(live["path"]) != norm(alert_image):
        log(f"PID {pid} is now {live['path']}, alert was for {alert_image}, not killing")
        sys.exit(0)

    # Protected processes, matched by full path
    live_path = os.path.normcase(live["path"])
    if live_path in PROTECTED_PATHS or live_path.startswith(PROTECTED_PREFIXES):
        log(f"PID {pid} ({live['path']}) is protected, not killing")
        sys.exit(0)

    r = subprocess.run(["taskkill", "/PID", pid, "/F"],
                       capture_output=True, text=True)
    log(f"killed PID {pid} ({live['path']}, original={live['original']}, "
        f"sha256={live['sha256']}): {r.stdout.strip()} {r.stderr.strip()}")


main()
