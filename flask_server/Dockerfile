# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install supervisord
RUN apt-get update && apt-get install -y supervisor

# Create the /app/logs directory
RUN mkdir -p /app/logs

# Copy the supervisor configuration file
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose the port that the app runs on
EXPOSE 8080

# Run supervisord
CMD ["/usr/bin/supervisord"]

