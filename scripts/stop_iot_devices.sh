#!/bin/bash

# Stop and remove all IoT device containers
docker rm -f $(docker ps -a -q --filter "ancestor=iot-device")