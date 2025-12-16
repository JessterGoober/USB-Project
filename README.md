## Suspicious USB Checker
- Author: Jessica Soto
- Course: CYB333 Security Automation

#### Project Overview

The Suspicious USB Checker is a simple security automation script designed to monitor a Windows system for newly connected USB devices. When a USB device is detected, the script automatically logs the device information and classifies it as either APPROVED or SUSPICIOUS based on a predefined allowlist. This automation helps demonstrate how removable media monitoring can reduce reliance on manual inspection and improve security awareness.

## How the Script Works

1. The script continuously monitors USB devices connected to the system.
2. When a new USB device is detected, it collects:
    - Device ID
    - Device name
3. The device is compared against:
    - An approved device list (e.g., CAC reader)
    - An ignore list for internal or non-relevant devices
4. The result is:
    - Printed to the terminal
    - Logged to a file for auditing purposes

### Device Classification Logic
- APPROVED:
Common Access Card (CAC) readers used for government authentication.

- SUSPICIOUS:
Personal devices such as mobile phones or unapproved USB input devices.

- IGNORED:
Internal system components such as root hubs, Bluetooth adapters, and the host laptop.

### Requirements
- Windows 11 operating system
- Python 3.13.5
- PowerShell

## How to Run

From the project directory, run:
python usb_script.py

The script will begin monitoring immediately.

To stop the script, press:
CTRL + C

The program exits cleanly without error messages.

Log File
All detected USB devices are written to:
usb_log.txt

Each entry includes:
- Timestamp
- Device ID
- Device name
- Classification status (APPROVED or SUSPICIOUS)

### Example Log Output
- New USB detected - DeviceID: USB\VID_0BDA&PID_0165..., Name: Microsoft Usbccid Smartcard Reader (WUDF), Status: APPROVED
- New USB detected - DeviceID: USB\VID_05AC&PID_12A8..., Name: Apple iPhone, Status: SUSPICIOUS

#### Security Relevance
Unauthorized USB devices are a common attack vector for malware introduction and data exfiltration. Automating the detection and classification of USB devices improves endpoint security by enforcing removable media policies and providing an auditable record of device activity.
