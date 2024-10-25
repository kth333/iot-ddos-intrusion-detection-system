# Use TensorFlow image as the base
FROM tensorflow/tensorflow:2.9.0

# Set the working directory inside the container
WORKDIR /app

# Copy the entire project into the container
COPY . /app

# Install necessary system packages and Python dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    gfortran \
    libblas-dev \
    liblapack-dev \
    libpcap-dev \
    iptables \
    net-tools \
    iproute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \
    scapy==2.4.5 \
    pandas==1.3.0 \
    joblib==1.1.0 \
    scikit-learn==1.2.0 \
    loguru==0.6.0

# Expose ports if the IDS listens on any specific ports
EXPOSE 1883

# Run the IDS script when the container starts
CMD ["python", "/app/ids/ids.py"