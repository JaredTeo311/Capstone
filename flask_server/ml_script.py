import pandas as pd
import re
from datetime import datetime

# Path to the traffic logs file
log_file_path = "/app/tmp/all_traffic_logs.txt"
# Path to save the output from ML script
output_file_path = "/app/tmp/ml_script_output.txt"

# Regular expression patterns to match the log lines
pattern_with_timestamp = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}) IP.*')
pattern_without_timestamp = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+) > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\S+): Flags \[(\S+)\], cksum.*length (\d+)')

# Function to parse log entry
def parse_log_entry(log_entry):
    try:
        # First try to match the pattern with a timestamp
        match = pattern_with_timestamp.match(log_entry)
        if match:
            timestamp = match.group(1)
            rest_of_log = log_entry[len(timestamp):].strip()
        else:
            # If no timestamp, try to match without timestamp pattern
            timestamp = None
            rest_of_log = log_entry.strip()
        
        # Match and extract details from the rest of the log
        match = pattern_without_timestamp.match(rest_of_log)
        if match:
            source_ip = match.group(1)
            source_port = match.group(2)
            destination_ip = match.group(3)
            destination_port = match.group(4)
            flags = match.group(5)
            packet_size = match.group(6)

            # Use current time if no timestamp is present
            if not timestamp:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            
            return {
                'Timestamp': timestamp,
                'Source IP address': source_ip,
                'Destination IP address': destination_ip,
                'Source port': source_port,
                'Destination port': destination_port,
                'Protocol': 'TCP',  # Assuming TCP based on the logs
                'Packet size': packet_size,
                'Flags': flags
            }
        else:
            raise ValueError("Log entry doesn't match the expected format")
    except Exception as e:
        print(f"Failed to parse log entry: {log_entry} due to {e}")
        return None

# Read and parse the log file
parsed_entries = []
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        parsed_entry = parse_log_entry(line)
        if parsed_entry:
            parsed_entries.append(parsed_entry)

# Check if any valid entries were parsed
if parsed_entries:
    # Convert parsed entries to a DataFrame
    df = pd.DataFrame(parsed_entries)

    # Print to see the DataFrame
    print(df.head())

    # Perform basic anomaly detection using Isolation Forest (example)
    from sklearn.ensemble import IsolationForest

    # Assuming packet size is the feature for simplicity
    df['Packet size'] = df['Packet size'].astype(int)
    model = IsolationForest(contamination=0.1)
    df['anomaly'] = model.fit_predict(df[['Packet size']])

    # Save the results to the output file
    df.to_csv(output_file_path, index=False)
    print(f"Anomaly detection completed. Results saved to {output_file_path}")
else:
    print("No valid log entries found.")


