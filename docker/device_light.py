import paho.mqtt.client as mqtt
import time

BROKER_ADDRESS = "mqtt-broker"
TOPIC = "iot/light/state"

client = mqtt.Client("SmartLight")

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

state = "OFF"

while True:
    state = "ON" if state == "OFF" else "OFF"
    client.publish(TOPIC, f"light_state: {state}")
    print(f"Published: light_state: {state}")
    time.sleep(7)
