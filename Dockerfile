FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Install iproute2 and tcpdump
RUN apt-get update && apt-get install -y iproute2 tcpdump

COPY proxy_logging_service.py proxy_logging_service.py

CMD ["python", "proxy_logging_service.py"]

