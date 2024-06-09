from flask import Flask, request, jsonify
import logging
import os

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_server')

# Path to save all traffic logs
log_file_path = "/app/tmp/all_traffic_logs.txt"

# Ensure the directory exists
os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

@app.route('/logs', methods=['POST'])
def receive_logs():
    log_data = request.get_json()
    if log_data:
        for log_entry in log_data:
            # Print all received logs
            logger.info(f"Received log: {log_entry}")
            try:
                # Write the raw log entry to the file
                with open(log_file_path, 'a') as log_file:
                    log_file.write(log_entry + '\n')
                logger.info(f"Saved log entry to file: {log_entry}")
            except Exception as e:
                logger.error(f"Error writing log entry to file: {log_entry} - {e}")
        return jsonify({"status": "logs received"}), 200
    else:
        return jsonify({"status": "no logs received"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

