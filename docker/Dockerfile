FROM python:3.8-slim

# Install dependencies
RUN pip install --no-cache-dir paho-mqtt

# Copy the device simulation script
COPY device.py /device.py

# Set the working directory
WORKDIR /

# Run the device simulation script
CMD ["python", "/device.py"]