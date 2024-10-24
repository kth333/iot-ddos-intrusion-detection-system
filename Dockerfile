# Use TensorFlow image as the base
FROM tensorflow/tensorflow:2.12.0

# Set the working directory inside the container
WORKDIR /app

# Copy the entire project into the container
COPY . /app

# Disable problematic repositories and install necessary packages and dependencies
RUN rm /etc/apt/sources.list.d/cuda.list || true && \
    apt-get update && apt-get install -y \
    iptables \
    net-tools \
    iproute2 \
    libpcap-dev \
    && pip install --no-cache-dir \
    scapy==2.4.5 \
    pandas==1.3.0 \
    joblib==1.1.0 \
    loguru==0.6.0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Expose ports if the IDS listens on any specific ports
EXPOSE 1883

# Run the IDS script when the container starts
CMD ["python", "/app/ids/ids.py"]



























