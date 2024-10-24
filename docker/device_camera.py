import paho.mqtt.client as mqtt
import time
import random

BROKER_ADDRESS = "mqtt-broker"  # This should be the name of the MQTT broker service in Docker Compose
TOPIC = "iot/sensor/temperature"

client = mqtt.Client("TemperatureSensor")
client.connect(BROKER_ADDRESS)

while True:
	temperature = round(random.uniform(20.0, 30.0), 2)
	client.publish(TOPIC, f"temperature: {temperature}")
	print(f"Published: temperature: {temperature}")
	time.sleep(5)
