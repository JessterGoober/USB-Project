"""
Suspicious USB Checker
Author: Jessica Soto
Course: CYB333 Security Automation

Description:
This script monitors a Windows system for USB devices. When a new USB device is detected,
it logs the device information and marks it as APPROVED or SUSPICIOUS based on a simple
allowlist. Common internal or noisy devices are filtered out to keep output readable.
"""

import subprocess
import time
import logging

# -----------------------------
# Configuration
# -----------------------------

LOG_FILE = "usb_log.txt"

# Approved devices (CAC reader only)
APPROVED_DEVICES = [
    "Usbccid Smartcard Reader",
    "VID_0BDA&PID_0165",
]

# Ignored devices (common internal devices)
IGNORE_KEYWORDS = [
    "Root Hub",
    "USB Composite Device",
    "Generic USB Hub",
    "Host Controller",
    "Bluetooth",
    "Integrated",
    "UCSI",
    "Razer Blade 14",
]

POLL_INTERVAL_SECONDS = 5

# -----------------------------
# Logging setup
# -----------------------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# -----------------------------
# Helper functions
# -----------------------------

def run_powershell(ps_command: str) -> str:
    """Runs a PowerShell command and returns stdout as text."""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_command],
        capture_output=True,
        text=True
    )
    return (completed.stdout or "").strip()


def get_usb_devices():
    """
    Uses PowerShell to query Win32_PnPEntity for USB devices.
    Returns a list of dictionaries:
    [{"device_id": "...", "name": "..."}, ...]
    """
    ps = r"""
    Get-CimInstance Win32_PnPEntity |
      Where-Object { $_.DeviceID -like 'USB*' } |
      Select-Object Name, DeviceID |
      ForEach-Object { "$($_.Name)||$($_.DeviceID)" }
    """

    raw = run_powershell(ps)
    if not raw:
        return []

    devices = []
    for line in raw.splitlines():
        if "||" not in line:
            continue
        name, device_id = line.split("||", 1)
        devices.append({
            "name": (name or "").strip(),
            "device_id": (device_id or "").strip()
        })

    return devices


def is_ignored(device) -> bool:
    """Returns True if device matches ignore list."""
    name = device.get("name", "")
    dev_id = device.get("device_id", "")
    haystack = f"{name} {dev_id}".lower()
    return any(k.lower() in haystack for k in IGNORE_KEYWORDS)


def classify_device(device) -> str:
    """Returns APPROVED or SUSPICIOUS based on allowlist."""
    name = device.get("name", "")
    dev_id = device.get("device_id", "")
    haystack = f"{name} {dev_id}".lower()

    for approved in APPROVED_DEVICES:
        if approved.lower() in haystack:
            return "APPROVED"

    return "SUSPICIOUS"


def log_new_device(device):
    """Logs a newly detected USB device."""
    status = classify_device(device)
    message = (
        f"New USB detected - "
        f"DeviceID: {device.get('device_id','')}, "
        f"Name: {device.get('name','')}, "
        f"Status: {status}"
    )
    logging.info(message)
    print(message)

# -----------------------------
# Main loop
# -----------------------------

def main():
    print("Starting Suspicious USB Checker...")
    print(f"Logging to: {LOG_FILE}")
    print("Press CTRL + C to stop monitoring.\n")

    seen = set()

    try:
        while True:
            devices = get_usb_devices()

            for d in devices:
                if is_ignored(d):
                    continue

                device_key = (d.get("device_id", ""), d.get("name", ""))
                if device_key not in seen:
                    seen.add(device_key)
                    log_new_device(d)

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\nUSB monitoring stopped by user.")


if __name__ == "__main__":
    main()
