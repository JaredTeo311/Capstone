#!/bin/bash

# Start the Flask server in the background
python flask_server.py &

# Start the machine learning script
python ml_script.py

