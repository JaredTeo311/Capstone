import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta
from tqdm import tqdm
import re

# Paths for log files
filtered_log_file_path = "/home/jared/oai-cn5g/flask_server/tmp/filtered_traffic_logs.txt"
malicious_log_file_path = "/home/jared/oai-cn5g/flask_server/tmp/malicious_traffic_logs.txt"
anomalies_output_file = "/home/jared/oai-cn5g/flask_server/results/anomalies_detected.txt"
variables_output_file = "/home/jared/oai-cn5g/flask_server/results/packet_variables.txt"
malicious_variables_output_file = "/home/jared/oai-cn5g/flask_server/results/malicious_packet_variables.txt"
matches_output_file = "/home/jared/oai-cn5g/flask_server/results/matches.txt"

# Function to read packet variables from a text file
def read_packet_variables(file_path):
    print(f"Reading packet variables from {file_path}...")
    entries = []
    entry = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                key, value = line.split('=', 1)
                entry[key] = value
            else:
                if entry:
                    entries.append(entry)
                    entry = {}
    if entry:
        entries.append(entry)
    return pd.DataFrame(entries)

# Function to parse the TXT log file
def parse_log_file(file_path, is_malicious=False):
    print(f"Parsing {'malicious ' if is_malicious else ''}log file...")
    entries = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        if is_malicious:
            for line in lines:
                parsed_packet = parse_malicious_packet(line.strip())
                if parsed_packet:
                    entries.append(parsed_packet)
        else:
            packet = []
            for line in lines:
                if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}', line):
                    if packet:
                        parsed_packet = parse_packet(packet)
                        if parsed_packet:
                            entries.append(parsed_packet)
                    packet = [line.strip()]
                else:
                    packet.append(line.strip())
            if packet:
                parsed_packet = parse_packet(packet)
                if parsed_packet:
                    entries.append(parsed_packet)
    return pd.DataFrame(entries)

def parse_packet(packet):
    if len(packet) != 2:
        return None

    first_line, details = packet

    if "ARP" in first_line:
        return None

    try:
        # Parse the first line for additional details
        timestamp = ' '.join(first_line.split(' ')[:2]).split('.')[0]
        tos = re.search(r'tos (\S+)', first_line).group(1) if "tos " in first_line else ""
        ttl = re.search(r'ttl (\d+)', first_line).group(1) if "ttl " in first_line else ""
        id_ = re.search(r'id (\d+)', first_line).group(1) if "id " in first_line else ""
        offset = re.search(r'offset (\d+)', first_line).group(1) if "offset " in first_line else ""
        flags = re.search(r'flags \[(.*?)\]', first_line).group(1) if "flags [" in first_line else ""
        proto = re.search(r'proto (\w+)', first_line).group(1) if "proto " in first_line else ""
        length = re.search(r'length (\d+)', first_line).group(1) if "length " in first_line else ""

        # Parse the second line for src, dst, and other details
        src_dst = details.split('>')[0].strip()
        dst_dst = details.split('>')[1].split(':')[0].strip()
        flags2 = re.search(r'Flags \[(.*?)\]', details).group(1) if "Flags [" in details else ""
        seq = re.search(r'seq (\d+)', details).group(1) if "seq " in details else ""
        ack = re.search(r'ack (\d+)', details).group(1) if "ack " in details else ""
        win = re.search(r'win (\d+)', details).group(1) if "win " in details else ""
        length2 = re.search(r'length (\d+)', details).group(1) if "length " in details else ""

        if src_dst.count('.') == 3:
            src_ip, src_port = src_dst, ''
        else:
            src_ip, src_port = src_dst.rsplit('.', 1)
        
        if dst_dst.count('.') == 3:
            dst_ip, dst_port = dst_dst, ''
        else:
            dst_ip, dst_port = dst_dst.rsplit('.', 1)
    except (ValueError, IndexError) as e:
        print(f"Skipping malformed packet: {details} - Error: {e}")
        return None

    return {
        'timestamp': timestamp,
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'protocol': proto,
        'tos': tos,
        'ttl': ttl,
        'id': id_,
        'offset': offset,
        'flags': flags,
        'length': length,
        'flags2': flags2,
        'seq': seq,
        'ack': ack,
        'win': win,
        'length2': length2,
        'details': details
    }

def parse_malicious_packet(line):
    try:
        parts = line.split()
        timestamp = ' '.join(parts[:2])
        src_ip = parts[2]
        dst_ip = parts[4].strip(':')
        protocol = parts[6]
        details = ' '.join(parts[7:])
        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'details': details
        }
    except ValueError as e:
        print(f"Skipping malformed malicious log line: {line} - Error: {e}")
        return None

# Function to write packet variables to a text file
def write_packet_variables(entries, output_file):
    # Clear the file before writing new content
    with open(output_file, 'w') as file:
        pass

    # Write the packet variables
    with open(output_file, 'a') as file:
        for entry in entries:
            for key, value in entry.items():
                file.write(f"{key}={value}\n")
            file.write("\n")  # Add a blank line between packets


# Function to detect anomalies based on multiple rules
def detect_anomalies(entries):
    print("Detecting anomalies...")
    anomalies = []
    anomalies.extend(rule_high_frequency(entries))
    anomalies.extend(rule_large_packets(entries))
    anomalies.extend(rule_port_scan(entries))
    anomalies.extend(rule_ip_not_in_subnet(entries))
    anomalies.extend(rule_fake_amf_insert(entries))
    
    # Remove duplicates
    anomalies_df = pd.DataFrame(anomalies).drop_duplicates()
    return anomalies_df
    
# Rule to detect high frequency traffic
def rule_high_frequency(entries, threshold=10, window=1):
    print("Applying high frequency rule...")
    anomalies = []
    entries['timestamp'] = pd.to_datetime(entries['timestamp'])
    
    for i, entry in tqdm(entries.iterrows(), total=entries.shape[0], desc="High Frequency Check"):
        src_ip = entry['src_ip']
        dst_ip = entry['dst_ip']
        timestamp = entry['timestamp']
        
        window_start = timestamp - timedelta(seconds=window)
        window_end = timestamp + timedelta(seconds=window)

        count = ((entries['src_ip'] == src_ip) & (entries['dst_ip'] == dst_ip) & 
                 (entries['timestamp'] >= window_start) & (entries['timestamp'] <= window_end)).sum()

        if count > threshold:
            entry['anomaly'] = 'High Frequency'
            anomalies.append(entry)

    return anomalies

# Rule to detect large packets
def rule_large_packets(entries, size_threshold=1000):
    print("Applying large packet rule...")
    anomalies = []
    for i, entry in tqdm(entries.iterrows(), total=entries.shape[0], desc="Large Packet Check"):
        length = entry.get('length', '')
        length2 = entry.get('length2', '')
        
        try:
            if length and int(length) > size_threshold:
                entry['anomaly'] = 'Large Packet'
                anomalies.append(entry)
            elif length2 and int(length2) > size_threshold:
                entry['anomaly'] = 'Large Packet'
                anomalies.append(entry)
        except ValueError:
            continue
    return anomalies

# Rule to detect port scan
def rule_port_scan(entries, threshold=10, window=1):
    print("Applying port scan rule...")
    anomalies = []
    entries['timestamp'] = pd.to_datetime(entries['timestamp'])

    for i, entry in tqdm(entries.iterrows(), total=entries.shape[0], desc="Port Scan Check"):
        src_ip = entry['src_ip']
        dst_ip = entry['dst_ip']
        timestamp = entry['timestamp']

        window_start = timestamp - timedelta(seconds=window)
        window_end = timestamp + timedelta(seconds=window)

        filtered_entries = entries[(entries['src_ip'] == src_ip) & (entries['dst_ip'] == dst_ip) & 
                                   (entries['timestamp'] >= window_start) & (entries['timestamp'] <= window_end)]

        port_count = filtered_entries['dst_port'].nunique()

        if port_count > threshold:
            entry['anomaly'] = 'Port Scan'
            anomalies.append(entry)

    return anomalies

# Rule to detect IP addresses not in the subnet
def rule_ip_not_in_subnet(entries, subnet="192.168.70"):
    print("Applying IP not in subnet rule...")
    anomalies = []
    for i, entry in tqdm(entries.iterrows(), total=entries.shape[0], desc="IP Not in Subnet Check"):
        src_ip = entry['src_ip']
        dst_ip = entry['dst_ip']
        if not src_ip.startswith(subnet) or not dst_ip.startswith(subnet):
            entry['anomaly'] = 'IP Not in Subnet'
            anomalies.append(entry)
    return anomalies

def rule_fake_amf_insert(entries):
    print("Applying Fake AMF Insert detection rule...")
    anomalies = []
    for i, entry in tqdm(entries.iterrows(), total=entries.shape[0], desc="Fake AMF Insert Check"):
        details = entry['details']
        if pd.isna(details):
            continue
        if (
            'PUT' in details and
            'Content-Type: application/json' in details and
            '"nfType":"AMF"' in details and
            '"nfStatus":"REGISTERED"' in details
        ):
            anomalies.append(entry)
    return anomalies
# Function to compare normal and malicious entries
def compare_entries(normal_entries, malicious_entries):
    print("Comparing normal and malicious entries...")
    matches = []
    for i, normal in normal_entries.iterrows():
        for j, malicious in malicious_entries.iterrows():
            if (normal['timestamp'] == malicious['timestamp'] and
                normal['src_ip'] == malicious['src_ip'] and
                normal['dst_ip'] == malicious['dst_ip']):
                matches.append(normal.to_dict())
    return matches

def main():
    log_entries = parse_log_file(filtered_log_file_path)
    write_packet_variables(log_entries.to_dict(orient='records'), variables_output_file)

    malicious_entries = parse_log_file(malicious_log_file_path, is_malicious=True)
    write_packet_variables(malicious_entries.to_dict(orient='records'), malicious_variables_output_file)

    print("Log Entries DataFrame sample:", log_entries.head())
    print("Malicious Entries DataFrame sample:", malicious_entries.head())

    # Filter log entries for destination IP 192.168.70.130
    log_entries['timestamp'] = pd.to_datetime(log_entries['timestamp'])
    log_entries = log_entries[(log_entries['dst_ip'] == "192.168.70.130")]

    anomalies = detect_anomalies(log_entries)

    print("Anomalies DataFrame sample after detection:", anomalies.head())

    # Save anomalies to file
    anomalies.to_csv(anomalies_output_file, index=False, sep=' ')
    #print(f"Anomalies saved to {anomalies_output_file}")

    #matches = compare_entries(anomalies, malicious_entries)

    #print(f"Number of matches: {len(matches)}")
    #with open(matches_output_file, 'w') as file:
        #for match in matches:
            #for key, value in match.items():
                #file.write(f"{key}={value}\n")
            #file.write("\n")  # Add a blank line between matches

    #print(f"Matches saved to {matches_output_file}")

if __name__ == "__main__":
    main()
