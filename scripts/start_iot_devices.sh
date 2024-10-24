#!/bin/bash

# Build the Docker image
docker build -t iot-device ../docker/

# Run multiple instances of the IoT device container
for i in {1..5}
do
   docker run -d --name iot-device-$i iot-device
done