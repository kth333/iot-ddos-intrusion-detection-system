import paho.mqtt.client as mqtt
import time
import random

BROKER_ADDRESS = "localhost"  # Replace with your MQTT broker IP if not running locally
TOPIC = "iot/device/data"

client_id = f"iot-device-{random.randint(1000, 9999)}"
client = mqtt.Client(client_id)

try:
    client.connect(BROKER_ADDRESS)
    print(f"{client_id} connected to MQTT Broker at {BROKER_ADDRESS}")
except Exception as e:
    print(f"{client_id} could not connect to MQTT Broker: {e}")
    exit(1)

try:
    while True:
        data = random.uniform(20.0, 30.0)  # Simulated sensor data
        message = f"Sensor reading from {client_id}: {data}"
        client.publish(TOPIC, message)
        print(f"{client_id} published: {message} to topic: {TOPIC}")
        time.sleep(5)  # Send data every 5 seconds
except KeyboardInterrupt:
    client.disconnect()
    print(f"{client_id} disconnected from MQTT Broker")