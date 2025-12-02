#!/usr/bin/env python3
# Small SDN/MTD metrics script for Mininet VM
# Monitors:
#   ✔ Ryu CPU & memory
#   ✔ Flow table size
#   ✔ Blocked IP counters
#   ✔ PPS rate on switch ports
#   ✔ Auto-refresh every second

import os
import time
import json
import subprocess
from collections import defaultdict

RYU_PROCESS_NAME = "ryu-manager"
SWITCH_NAME = "s1"

def get_ryu_usage():
    """Return CPU% and memory usage for the Ryu controller."""
    try:
        # ps -C ryu-manager -o %cpu,%mem --no-headers
        output = subprocess.check_output(
            f"ps -C {RYU_PROCESS_NAME} -o %cpu,%mem --no-headers",
            shell=True
        ).decode().strip()

        if not output:
            return (0, 0)

        cpu, mem = output.split()
        return (cpu, mem)

    except:
        return (0, 0)


def get_flow_count():
    """Count the number of flows in the switch."""
    try:
        output = subprocess.check_output(
            f"sudo ovs-ofctl dump-flows {SWITCH_NAME}",
            shell=True
        ).decode()

        # ignore header line
        lines = output.strip().split("\n")[1:]
        return len(lines)

    except:
        return 0


def get_blocked_ips():
    """Reads blocked IPs from the controller's internal file (if present)."""

    # If your controller writes blocked IPs to a file:
    BLOCK_FILE = "/tmp/mtd_blocked_ips.json"

    if not os.path.exists(BLOCK_FILE):
        return []

    try:
        with open(BLOCK_FILE, "r") as f:
            data = json.load(f)
            return data.get("blocked_ips", [])
    except:
        return []


def get_port_pps():
    """Get packets-per-second for switch ports."""
    pps = defaultdict(int)

    try:
        output = subprocess.check_output(
            f"sudo ovs-ofctl dump-ports {SWITCH_NAME}",
            shell=True
        ).decode()

        for line in output.split("\n"):
            if "rx pkts" in line:
                parts = line.split()
                port = parts[0].strip("():")
                rx = int(parts[3].split("=")[-1])
                pps[port] = rx

        return pps

    except:
        return {}


def print_banner():
    print("\033[92m==============================\033[0m")
    print("\033[96m   MTD LIVE METRICS MONITOR   \033[0m")
    print("\033[92m==============================\033[0m")


def run_monitor():
    print_banner()

    last_pps = {}

    while True:
        cpu, mem = get_ryu_usage()
        flow_count = get_flow_count()
        blocked = get_blocked_ips()
        pps = get_port_pps()

        print("\n\033[93m--- Metrics Update ---\033[0m")

        print(f"Ryu CPU%: {cpu}")
        print(f"Ryu MEM%: {mem}")
        print(f"Flow Count: {flow_count}")

        if blocked:
            print("\033[91mBlocked IPs:\033[0m", blocked)
        else:
            print("Blocked IPs: None")

        # PPS change
        print("\nPacket Rate (per port):")
        for port in pps:
            last = last_pps.get(port, 0)
            delta = pps[port] - last
            print(f"  Port {port}: {delta} pps")
            last_pps[port] = pps[port]

        time.sleep(1)


if __name__ == "__main__":
    run_monitor()
