import paho.mqtt.client as mqtt
import time
import random

BROKER_ADDRESS = "mqtt-broker"
TOPIC = "iot/camera/motion"

client = mqtt.Client("CameraSensor")
client.connect(BROKER_ADDRESS)

# Retry mechanism to wait for broker connection
connected = False
while not connected:
    try:
        client.connect(BROKER_ADDRESS)
        connected = True
        print("Connected to MQTT broker")
    except Exception as e:
        print(f"Connection failed, retrying in 5 seconds... {e}")
        time.sleep(5)  # Wait for 5 seconds before retrying

while True:
    motion_detected = random.choice([True, False])
    client.publish(TOPIC, f"motion_detected: {motion_detected}")
    print(f"Published: motion_detected: {motion_detected}")
    time.sleep(10)