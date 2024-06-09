import os
import requests
import subprocess

# Function to run tcpdump and capture logs
def capture_logs(interface, subnet, log_file_path):
    command = [
    "tcpdump", "-i", interface, f"net {subnet}",
    "-s", "0", "-vv", "-l", "-A", "-x", "-tttt"
]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    with open(log_file_path, 'w') as log_file:
        while True:
            line = process.stdout.readline().decode('utf-8', errors='replace').strip()
            if line and is_valid_log_entry(line):
                log_file.write(line + '\n')
                log_file.flush()
                print(f"Captured log: {line}")
                send_log_to_server(line)

# Function to check if the log entry is valid
def is_valid_log_entry(log_entry):
    valid_keywords = ['IP', 'Flags', 'length']
    return any(keyword in log_entry for keyword in valid_keywords)

# Function to send logs to the Flask server
def send_log_to_server(log_entry):
    try:
        logs = [log_entry]  # Wrapping in a list to send as JSON array
        response = requests.post("http://192.168.70.142:8080/logs", json=logs)
        response.raise_for_status()
        print(f"Successfully sent log entry: {log_entry}")
    except requests.RequestException as e:
        print(f"Error sending logs to Flask server: {e}")

if __name__ == "__main__":
    INTERFACE = os.getenv("INTERFACE", "demo-oai")
    SUBNET = "192.168.70.0/24"
    LOG_FILE_PATH = "/var/log/traffic_logs.txt"
    
    print(f"Starting traffic capture using tcpdump on interface {INTERFACE} for subnet {SUBNET}")
    capture_logs(INTERFACE, SUBNET, LOG_FILE_PATH)

