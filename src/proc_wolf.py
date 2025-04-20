#!/usr/bin/env python3

import os
import time
import signal
import psutil
from datetime import datetime

# Set the processes you want to monitor
TARGET_PROCESSES = {
    "badprocess.exe": {"kills": 0, "severity": 0},
    "evilscript.py": {"kills": 0, "severity": 0},
    "worm.bat": {"kills": 0, "severity": 0}
}

# Timing
CHECK_INTERVAL = 5  # seconds
LOG_FILE = os.path.join(os.environ.get("APPDATA", "C:\\"), "proc_wolf.log")

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {msg}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def escalate(proc_name, proc_obj):
    info = TARGET_PROCESSES[proc_name]
    info["kills"] += 1

    if info["kills"] < 3:
        log(f"[L1] Killing {proc_name} (PID {proc_obj.pid}) - Soft kill")
        proc_obj.terminate()
    elif info["kills"] < 6:
        log(f"[L2] Killing {proc_name} (PID {proc_obj.pid}) - Force kill")
        proc_obj.kill()
    else:
        info["severity"] += 1
        log(f"[L3] Process {proc_name} keeps respawning! Severity escalated to {info['severity']}.")
        try:
            os.system(f"taskkill /F /IM {proc_name}")  # fallback for Windows
        except Exception as e:
            log(f"[ERROR] Failed hard kill on {proc_name}: {e}")

def monitor():
    log("Proc-Wolf started. Watching for suspicious processes...")
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            pname = proc.info['name']
            if pname in TARGET_PROCESSES:
                try:
                    escalate(pname, proc)
                except Exception as e:
                    log(f"[ERROR] Could not handle {pname}: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        log("Proc-Wolf terminated manually.")
