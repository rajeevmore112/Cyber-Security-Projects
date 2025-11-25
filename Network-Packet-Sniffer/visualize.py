# visualize.py
"""
Read packets.db and generate protocol_dist.png and top_src.png using pandas + matplotlib.
"""
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

DB_FILE = "packets.db"

def load_df():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT timestamp, src_ip, protocol FROM packets", conn)
    conn.close()
    if df.empty:
        print("[WARN] No rows in DB - nothing to plot.")
    else:
        df['time'] = pd.to_datetime(df['timestamp'], unit='s')
    return df

def plot_proto(df):
    proto_counts = df['protocol'].value_counts().head(20)
    plt.figure(figsize=(8,4))
    proto_counts.plot(kind='bar')
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.tight_layout()
    out = "protocol_dist.png"
    plt.savefig(out)
    plt.close()
    print(f"[INFO] Saved {out}")

def plot_top_src(df):
    top_src = df['src_ip'].value_counts().head(20)
    plt.figure(figsize=(8,4))
    top_src.plot(kind='bar')
    plt.title("Top Source IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Count")
    plt.tight_layout()
    out = "top_src.png"
    plt.savefig(out)
    plt.close()
    print(f"[INFO] Saved {out}")

def main():
    df = load_df()
    if df.empty:
        return
    plot_proto(df)
    plot_top_src(df)

if __name__ == "__main__":
    main()
