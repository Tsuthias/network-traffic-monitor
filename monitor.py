import psutil
import time
from datetime import datetime

# Ports commonly associated with suspicious activity
SUSPICIOUS_PORTS = [4444, 1337, 6666]

LOG_FILE = "alerts.log"


def log_alert(message):
    """Write alert messages to a log file."""
    with open(LOG_FILE, "a") as file:
        file.write(f"{message}\n")


def get_process_name(pid):
    """Safely get process name from PID."""
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"


def monitor_connections():
    """Monitor active network connections and flag suspicious activity."""
    connections = psutil.net_connections()

    for conn in connections:
        if conn.status != "ESTABLISHED":
            continue

        if not conn.raddr or not conn.pid:
            continue

        local_ip, local_port = conn.laddr
        remote_ip, remote_port = conn.raddr
        process_name = get_process_name(conn.pid)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        info_msg = (
            f"[{timestamp}] [INFO] [{process_name}] "
            f"{local_ip}:{local_port} -> {remote_ip}:{remote_port}"
        )
        print(info_msg)

        # Alert logic
        if remote_port in SUSPICIOUS_PORTS:
            alert_msg = (
                f"[{timestamp}] [ALERT] [{process_name}] "
                f"Suspicious port detected: {remote_ip}:{remote_port}"
            )
            print(alert_msg)
            log_alert(alert_msg)


def main():
    print("Starting Network Monitor... Press Ctrl+C to stop.\n")

    while True:
        monitor_connections()
        print("-" * 50)
        time.sleep(5)


if __name__ == "__main__":
    main()