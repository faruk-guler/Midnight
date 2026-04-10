import os
import sys
import json
import time
import socket
import requests
import psutil
from datetime import datetime

# Configuration
BACKEND_URL = "http://localhost:8000/api/logs"  # Replace with actual Backend IP
INTERVAL = 5  # Seconds between scans
HOSTNAME = socket.gethostname()

def get_active_connections():
    """
    Collects active network connections and the processes that own them.
    Similar to the eBPF logger but using psutil for Windows.
    """
    connections = []
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == 'ESTABLISHED':
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                cmdline = " ".join(process.cmdline())
                user = process.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "unknown"
                cmdline = ""
                user = "unknown"

            entry = {
                "timestamp": datetime.now().isoformat(),
                "hostname": HOSTNAME,
                "os": "windows",
                "uid": 0,  # Windows uses SIDs, simplified for now
                "user": user,
                "pid": conn.pid,
                "comm": process_name,
                "cmdline": cmdline,
                "family": "ipv4" if conn.family == socket.AF_INET else "ipv6",
                "src_ip": conn.laddr.ip,
                "src_port": conn.laddr.port,
                "dst_ip": conn.raddr.ip,
                "dst_port": conn.raddr.port,
                "type": "network_connection"
            }
            connections.append(entry)
    return connections

def main():
    print(f"Midnight Windows Agent starting on {HOSTNAME}...")
    print(f"Sending logs to {BACKEND_URL}")
    
    seen_connections = set()

    while True:
        try:
            current_conns = get_active_connections()
            
            for conn in current_conns:
                # Create a unique key for the connection to avoid spamming the same event
                conn_key = f"{conn['pid']}-{conn['dst_ip']}-{conn['dst_port']}"
                
                if conn_key not in seen_connections:
                    # New connection detected
                    print(f"[NEW] {conn['comm']} -> {conn['dst_ip']}:{conn['dst_port']}")
                    
                    # Send to Backend
                    try:
                        requests.post(BACKEND_URL, json=conn, timeout=2)
                    except Exception as e:
                        print(f"Error sending log: {e}")
                    
                    seen_connections.add(conn_key)
            
            # Simple cache cleanup to avoid memory leak
            if len(seen_connections) > 1000:
                seen_connections.clear()
                
            time.sleep(INTERVAL)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Agent error: {e}")
            time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
