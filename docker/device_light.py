import paho.mqtt.client as mqtt
import time

BROKER_ADDRESS = "mqtt-broker"
TOPIC = "iot/light/state"

client = mqtt.Client("SmartLight")
client.connect(BROKER_ADDRESS)

state = "OFF"

while True:
	state = "ON" if state == "OFF" else "OFF"
	client.publish(TOPIC, f"light_state: {state}")
	print(f"Published: light_state: {state}")
	time.sleep(7)
