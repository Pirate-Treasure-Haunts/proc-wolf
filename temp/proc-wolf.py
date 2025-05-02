#!/usr/bin/env python3
import time
import psutil
import subprocess
import logging

# CONFIG
TARGET_NAMES = ['notepad.exe', 'sus.exe']  # replace with real targets
LOG_PATH = 'C:\\Users\\Phine\\proc-wolf.log'
CHECK_INTERVAL = 5  # seconds
MAX_WARNINGS = 3

# LOG SETUP
logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

warnings = {}

def kill_process(proc):
    try:
        proc.kill()
        logging.warning(f"Killed process: {proc.name()} (PID: {proc.pid})")
    except Exception as e:
        logging.error(f"Error killing {proc.name()} (PID: {proc.pid}): {e}")

def monitor():
    logging.info("proc-wolf started. Watching processes...")
    while True:
        found = False
        for proc in psutil.process_iter(['name', 'pid']):
            name = proc.info['name']
            pid = proc.info['pid']

            if name in TARGET_NAMES:
                found = True
                warnings[name] = warnings.get(name, 0) + 1
                logging.warning(f"[{name}] detected (PID {pid}) - warning #{warnings[name]}")

                if warnings[name] >= MAX_WARNINGS:
                    kill_process(proc)
                    warnings[name] = 0

        if not found:
            warnings.clear()

        time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    try:
        monitor()
    except KeyboardInterrupt:
        logging.info("proc-wolf stopped by user.")
