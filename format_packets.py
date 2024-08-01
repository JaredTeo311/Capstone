import os
import pandas as pd
import pyshark

# Paths to the pcap files
pcap_files = {
    "randomAMFInsert": "/home/jared/Desktop/presentation/packets/Attacks_randomAMFInsert.pcapng",
    "AMFLookingForUDM": "/home/jared/Desktop/presentation/packets/Attacks_AMFLookingForUDM.pcapng",
    "randomDataDump": "/home/jared/Desktop/presentation/packets/Attacks_randomDataDump.pcapng",
    "GetAllNFs": "/home/jared/Desktop/presentation/packets/Attacks_GetAllNFs.pcapng"
}

# Function to extract packets and convert to DataFrame
def extract_packets_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, decode_as={'tcp.port==8000': 'http'})
    packets = []
    for packet in cap:
        try:
            if 'HTTP' in packet:
                packet_info = {
                    "timestamp": packet.sniff_time,
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "src_port": packet.tcp.srcport,
                    "dst_port": packet.tcp.dstport,
                    "protocol": packet.transport_layer,
                    "details": packet.http.request_full_uri if hasattr(packet.http, 'request_full_uri') else str(packet.http)
                }
                packets.append(packet_info)
        except AttributeError:
            continue
    cap.close()
    return pd.DataFrame(packets)

# Extract packets and save to CSV
for attack_name, pcap_path in pcap_files.items():
    df = extract_packets_from_pcap(pcap_path)
    csv_path = f"/home/jared/Desktop/presentation/packets/{attack_name}_packets.csv"
    df.to_csv(csv_path, index=False)
    print(f"Extracted packets for {attack_name} saved to {csv_path}")
