import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

# Paths to the training data files
normal_traffic_file = "/app/logs/normal_traffic_logs.txt"
training_traffic_file = "/app/logs/training_traffic_logs.txt"
model_output_file = "/app/logs/isolation_forest_model.pkl"

# Function to parse the log files
def parse_log_file(file_path):
    # Regular expression patterns to match the log lines
    pattern_with_timestamp = re.compile(
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}) IP.*'
    )
    pattern_without_timestamp = re.compile(
        r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\w+): Flags \[(\S+)\], cksum.*length (\d+)'
    )

    def parse_log_entry(log_entry):
        try:
            match = pattern_with_timestamp.match(log_entry)
            if match:
                timestamp = match.group(1)
                rest_of_log = log_entry[len(timestamp):].strip()
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                rest_of_log = log_entry.strip()

            match = pattern_without_timestamp.match(rest_of_log)
            if match:
                source_ip = match.group(1)
                source_port = match.group(2)
                destination_ip = match.group(3)
                destination_port = match.group(4)
                flags = match.group(5)
                packet_size = int(match.group(6))

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
    
    parsed_entries = []
    with open(file_path, 'r') as log_file:
        for line in log_file:
            parsed_entry = parse_log_entry(line)
            if parsed_entry:
                parsed_entries.append(parsed_entry)
    
    return pd.DataFrame(parsed_entries)

# Parse the log files
normal_traffic_df = parse_log_file(normal_traffic_file)
training_traffic_df = parse_log_file(training_traffic_file)

# Label the data: 0 for normal, 1 for anomaly (assume we know the malicious entries in the training file)
normal_traffic_df['anomaly'] = 0
training_traffic_df['anomaly'] = 1

# Combine the datasets for training
training_data = pd.concat([normal_traffic_df, training_traffic_df])

# Train the Isolation Forest model
features = ['Packet size']  # Using packet size as the feature for simplicity
X = training_data[features]
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

# Save the trained model
with open(model_output_file, 'wb') as model_file:
    pickle.dump(model, model_file)

print("Model training completed. The model has been saved to", model_output_file)

