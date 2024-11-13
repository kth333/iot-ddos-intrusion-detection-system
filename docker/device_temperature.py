import paho.mqtt.client as mqtt
import time
import random

BROKER_ADDRESS = "mqtt-broker" 
TOPIC = "iot/sensor/temperature"

client = mqtt.Client("TemperatureSensor")

# Retry mechanism to wait for broker connection
connected = False
while not connected:
    try:
        client.connect(BROKER_ADDRESS)
        connected = True
        print("Connected to MQTT broker")
    except Exception as e:
        print(f"Connection failed, retrying in 5 seconds... {e}")
        time.sleep(5) 

while True:
    temperature = round(random.uniform(20.0, 30.0), 2)
    client.publish(TOPIC, f"temperature: {temperature}")
    print(f"Published: temperature: {temperature}")
    time.sleep(5)
