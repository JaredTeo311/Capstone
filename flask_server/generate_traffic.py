import subprocess
import time
import os
from scapy.all import IP, TCP, send

# Function to simulate a ping flood (ICMP flood)
def generate_ping_flood():
    print("Generating ping flood attack...")
    ip_list = ["192.168.70.129", "192.168.70.130", "192.168.70.131", "192.168.70.132"]
    for ip in ip_list:
        subprocess.run(["ping", "-f", "-c", "100", ip], capture_output=True)
    time.sleep(1)

# Function to simulate sending large packets
def generate_large_packets():
    print("Generating large packet traffic...")
    ip_list = ["192.168.70.129", "192.168.70.130", "192.168.70.131", "192.168.70.132"]
    for ip in ip_list:
        subprocess.run(["ping", "-s", "65000", "-c", "10", ip], capture_output=True)
    time.sleep(1)

# Function to simulate abnormal source IP traffic using Scapy
def generate_abnormal_source_traffic():
    print("Generating traffic with abnormal source IP...")
    ip_list = ["192.168.70.129", "192.168.70.130", "192.168.70.131", "192.168.70.132"]
    for ip in ip_list:
        for _ in range(50):  # Send 50 packets
            packet = IP(src="10.0.0.1", dst=ip) / TCP(dport=80, flags="S")
            send(packet, verbose=False)
        time.sleep(1)

# Function to filter out unwanted lines from the captured logs
def filter_logs(input_file, output_file):
    print("Filtering captured logs...")
    unwanted_keywords = [
        "HTTP/1.1", "Server:", "Date:", "Content-Type:", "Content-Length:", 
        "Connection:", "Host:", "User-Agent:", "Accept-Encoding:", "Accept:", 
        "POST", "GET"
    ]

    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        skip_next_lines = 0  # Counter to skip multiple lines after a match
        for line in infile:
            if any(keyword in line for keyword in unwanted_keywords):
                skip_next_lines = 1  # Skip the next line as well
                continue
            if skip_next_lines > 0:
                skip_next_lines -= 1
                continue
            outfile.write(line)

    print(f"Filtered logs saved to {output_file}")

# Function to capture traffic using tcpdump
def capture_traffic():
    print("Starting traffic capture...")
    interface = "demo-oai"
    subnet = "192.168.70.0/24"
    log_file_path = "/home/jared/oai-cn5g/flask_server/tmp/training_traffic_logs.txt"
    filtered_log_file_path = "/home/jared/oai-cn5g/flask_server/tmp/filtered_traffic_logs.txt"

    available_interfaces = subprocess.check_output(["ip", "link", "show"]).decode('utf-8')
    print(f"Available network interfaces:\n{available_interfaces}")
    
    if interface not in available_interfaces:
        print(f"Error: Interface {interface} not found. Please verify the interface name.")
        return

    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    
    tcpdump_command = [
        "tcpdump", "-i", interface, f"net {subnet}",
        "-s", "0", "-vv", "-l", "-tttt", "-n"
    ]
    with open(log_file_path, 'w') as log_file:
        tcpdump_process = subprocess.Popen(tcpdump_command, stdout=log_file, stderr=subprocess.PIPE)
    
        try:
            print("Generating normal traffic...")
            # Duration to run the capture in seconds (7 minutes)
            duration = 7 * 60
            start_time = time.time()  # Define start_time here

            while time.time() - start_time < duration / 2:
                time.sleep(1)  # Placeholder for normal traffic generation

            print("Switching to generating malicious traffic...")
            generate_ping_flood()
            generate_large_packets()
            generate_abnormal_source_traffic()
            
            print("Traffic generation complete.")
        finally:
            tcpdump_process.terminate()
            tcpdump_process.wait()
            print(f"Traffic logs saved to {log_file_path}")
            stderr_output = tcpdump_process.stderr.read().decode('utf-8')
            if stderr_output:
                print(f"tcpdump errors:\n{stderr_output}")
            
            # Filter out unwanted lines from the captured logs
            filter_logs(log_file_path, filtered_log_file_path)

if __name__ == "__main__":
    capture_traffic()

