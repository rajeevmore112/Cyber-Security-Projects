# simulate_scan.py
"""
Simple port-scan simulator using Scapy.
SAFE MODE: default target is 127.0.0.1 (localhost). Do NOT point at remote hosts.
Run as Administrator.
"""
import time
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0  # quiet

TARGET = "127.0.0.1"  # IMPORTANT: keep this as localhost for safety
PORTS = list(range(20, 45))  # small range for demo
DELAY = 0.05

def main():
    print(f"[INFO] Starting simulated scan against {TARGET} ports {PORTS[0]}-{PORTS[-1]}")
    for p in PORTS:
        pkt = IP(dst=TARGET) / TCP(dport=p, flags="S")
        resp = sr1(pkt, timeout=60)
        if resp is None:
            print(f"port {p}: no response")
        else:
            # response present
            rst_flag = resp.sprintf("%TCP.flags%")
            print(f"port {p}: resp flags={rst_flag}")
        time.sleep(DELAY)
    print("[INFO] Simulated scan finished.")

if __name__ == "__main__":
    main()
