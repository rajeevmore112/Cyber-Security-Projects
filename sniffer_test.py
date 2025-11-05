# sniffer.py
"""
Packet Sniffer with SQLite logging and simple anomaly detection.
Windows-friendly: will auto-detect Wi-Fi adapter if available, or use INTERFACE env var.
Run as Administrator on Windows.
"""

import os
import time
import sqlite3
import platform
from collections import defaultdict, deque
from subprocess import Popen, PIPE

from scapy.all import sniff, IP, TCP, UDP, get_if_list

# ---------- CONFIG ----------
DB_FILE = "packets.db"
ALERT_LOG = "alerts.log"
INTERFACE_ENV = "INTERFACE"   # optional: set this env var to specify iface name

# anomaly thresholds (tune to your environment)
WINDOW = 5            # seconds (sliding window)
PORT_THRESHOLD = 20    # distinct dst ports in WINDOW -> port scan
RATE_THRESHOLD = 50    # packets in WINDOW -> high rate
# ----------------------------

def parse_getmac_output(out_text):
    """
    Parse getmac /v /fo list output into a mapping:
    { Connection Name (friendly) : Transport Name (\\Device\\NPF_{...}) }
    Note: backslashes are escaped here (\\Device\\NPF_...) to avoid unicode-escape issues.
    """
    mapping = {}
    blocks = out_text.splitlines()
    # We'll accumulate current block's key-values until blank line
    cur = {}
    for line in blocks:
        line = line.strip()
        if not line:
            # end of block
            if 'Connection Name' in cur and 'Transport Name' in cur:
                mapping[cur['Connection Name']] = cur['Transport Name']
            cur = {}
            continue
        if ':' in line:
            k, v = line.split(':', 1)
            cur[k.strip()] = v.strip()
    # end final block
    if 'Connection Name' in cur and 'Transport Name' in cur:
        mapping[cur['Connection Name']] = cur['Transport Name']
    return mapping

def windows_find_wifi_transport():
    """
    Use 'getmac /v /fo list' to find the transport name for the Wi-Fi connection.
    Returns transport name string like '\\Device\\NPF_{GUID}' or None.
    """
    try:
        p = Popen(["getmac", "/v", "/fo", "list"], stdout=PIPE, stderr=PIPE, text=True)
        out, err = p.communicate(timeout=5)
    except Exception as e:
        print("[WARN] Failed to run getmac:", e)
        return None
    if not out:
        return None
    mapping = parse_getmac_output(out)
    # Try common Wi-Fi names
    candidates = ["Wi-Fi", "WiFi", "Wireless Network Connection", "Wireless", "WLAN","Ethernet"]
    for cname in candidates:
        if cname in mapping:
            print(f"[INFO] Found Windows connection '{cname}' -> transport {mapping[cname]}")
            return mapping[cname]
    # If exact names not found, try case-insensitive search
    for k, v in mapping.items():
        if 'wi' in k.lower() and 'fi' in k.lower():
            print(f"[INFO] Found Windows connection '{k}' -> transport {v}")
            return v
    # nothing
    return None

def pick_interface():
    # If user specified interface via env var, use it
    iface = os.getenv(INTERFACE_ENV)
    if iface:
        print(f"[INFO] Using interface from env: {iface}")
        return iface

    # On Windows, try to find Wi-Fi via getmac mapping
    if platform.system().lower().startswith("win"):
        wifi_transport = windows_find_wifi_transport()
        if wifi_transport:
            return wifi_transport

    # fallback: auto pick: first interface that isn't clearly a loopback adapter
    ifaces = get_if_list()
    print(f"[DEBUG] get_if_list(): {ifaces}")
    candidates = [i for i in ifaces if "Loopback" not in i and "Npcap Loopback" not in i and "Loopback" not in i]
    if candidates:
        print(f"[INFO] Auto-picked interface: {candidates[0]}")
        return candidates[0]
    print(f"[WARN] No candidate interface found from get_if_list(); defaulting to None (scapy chooses).")
    return None

def init_db():
    first = not os.path.exists(DB_FILE)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    if first:
        conn.execute('''
            CREATE TABLE packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER
            )
        ''')
        conn.commit()
        print(f"[INFO] Created DB {DB_FILE} and packets table.")
    else:
        print(f"[INFO] Using existing DB {DB_FILE}.")
    return conn

def insert_packet(conn, info):
    try:
        conn.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (info['timestamp'], info['src_ip'], info['dst_ip'], info['protocol'], info['src_port'], info['dst_port']))
        conn.commit()
    except Exception as e:
        print("[ERROR] DB insert failed:", e)

def extract_info(pkt):
    ts = time.time()
    src = pkt[IP].src if IP in pkt else None
    dst = pkt[IP].dst if IP in pkt else None
    proto = None
    sport = None
    dport = None
    if TCP in pkt:
        proto = 'TCP'
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = 'UDP'
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    else:
        proto = pkt.lastlayer().name if IP in pkt else pkt.summary()
    return {
        'timestamp': ts,
        'src_ip': src,
        'dst_ip': dst,
        'protocol': proto,
        'src_port': sport,
        'dst_port': dport
    }

# in-memory structures for quick detection
packet_times = defaultdict(deque)   # src_ip -> deque(timestamps)
port_deques = defaultdict(deque)    # src_ip -> deque((timestamp, dst_port))

def detect_anomaly(info):
    src = info['src_ip']
    now = info['timestamp']
    if not src:
        return None
    # packet rate
    dq = packet_times[src]
    dq.append(now)
    while dq and dq[0] < now - WINDOW:
        dq.popleft()
    # port diversity
    pdeque = port_deques[src]
    pdeque.append((now, info['dst_port']))
    while pdeque and pdeque[0][0] < now - WINDOW:
        pdeque.popleft()
    distinct_ports = {p for (t, p) in pdeque if p is not None}
    if len(distinct_ports) >= PORT_THRESHOLD:
        return ("PORT_SCAN", src, len(distinct_ports))
    if len(dq) >= RATE_THRESHOLD:
        return ("HIGH_RATE", src, len(dq))
    return None

def log_alert(msg):
    ts = time.ctime()
    line = f"{ts}: {msg}\n"
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(line)
    except Exception as e:
        print("[ERROR] Could not write to alert log:", e)

def pkt_callback(pkt):
    info = extract_info(pkt)
    # show summary to console (minimal)
    print(f"{time.strftime('%H:%M:%S')} {info['src_ip']} -> {info['dst_ip']} {info['protocol']} {info['dst_port']}")
    # insert into DB
    try:
        insert_packet(pkt_callback.conn, info)
    except Exception as e:
        print("[ERROR] insert_packet exception:", e)
    # anomaly detection
    anomaly = detect_anomaly(info)
    if anomaly:
        kind, src, val = anomaly
        alert_msg = f"[ALERT] {kind} detected from {src} (value={val})"
        print(alert_msg)
        log_alert(alert_msg)
        # optional: call email_alerts.send_email_alert(subject, body) if integrated

def main():
    iface = pick_interface()
    conn = init_db()
    pkt_callback.conn = conn
    print("[INFO] Starting sniffing... Press Ctrl+C to stop (or it will auto-stop after timeout if configured).")
    sniff_kwargs = dict(prn=pkt_callback, store=False, timeout=300)  # default 60s safe timeout for debugging
    if iface:
        sniff_kwargs['iface'] = iface
        print(f"[INFO] Using sniff iface: {iface}")
    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("[INFO] Keyboard interrupt received. Stopping sniff.")
    except Exception as e:
        print("[ERROR] sniff raised exception:", e)
    finally:
        try:
            conn.close()
        except:
            pass
        print("[INFO] Sniffer finished.")

if __name__ == "__main__":
    main()
