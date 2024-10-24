import numpy as np
import pandas as pd
from tensorflow import keras
from scapy.all import sniff, IP, TCP, UDP
import joblib
import logging
import subprocess

# Load the trained model
model = keras.models.load_model('/app/models/ddos_detection_model.keras')

# Load preprocessing objects
ohe = joblib.load('../models/ohe.joblib')  # OneHotEncoder used during training
scaler = joblib.load('../models/scaler.joblib')  # StandardScaler used during training

# Configure logging with rotation
from logging.handlers import RotatingFileHandler
handler = RotatingFileHandler('../logs/ids.log', maxBytes=5*1024*1024, backupCount=3)  # 5MB per file, 3 backups
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Device priority mapping
device_priorities = {
    '192.168.1.2': 'high',
    '192.168.1.3': 'medium',
    # Add other devices as needed
}

def preprocess_features(features):
    df = pd.DataFrame([features])
    categorical_cols = ['proto']
    numerical_cols = ['length', 'sport', 'dport']

    # Ensure all expected columns are present
    for col in categorical_cols + numerical_cols:
        if col not in df.columns:
            df[col] = 0

    # Encode categorical variables
    X_encoded = ohe.transform(df[categorical_cols])

    # Scale numerical features
    X_scaled = scaler.transform(df[numerical_cols])

    # Combine features
    X_preprocessed = np.hstack([X_scaled, X_encoded.toarray()])

    return X_preprocessed

def extract_features(packet):
    features = {}
    # Protocol
    if packet.haslayer(TCP):
        features['proto'] = 'tcp'
        features['sport'] = packet[TCP].sport
        features['dport'] = packet[TCP].dport
        features['flags'] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        features['proto'] = 'udp'
        features['sport'] = packet[UDP].sport
        features['dport'] = packet[UDP].dport
    else:
        features['proto'] = 'other'
        features['sport'] = 0
        features['dport'] = 0

    # Packet length
    features['length'] = len(packet)

    # Source and Destination IPs
    features['src_ip'] = packet[IP].src if packet.haslayer(IP) else '0.0.0.0'
    features['dst_ip'] = packet[IP].dst if packet.haslayer(IP) else '0.0.0.0'

    return features

def predict_and_act(packet):
    try:
        features = extract_features(packet)
        src_ip = features.get('src_ip', '0.0.0.0')

        # Preprocess features
        X_preprocessed = preprocess_features(features)

        # Predict
        prediction_prob = model.predict(X_preprocessed)[0][0]
        prediction = int(prediction_prob > 0.5)

        if prediction == 1:
            handle_attack(src_ip, prediction_prob)
        else:
            handle_normal(src_ip, prediction_prob)
    except Exception as e:
        logging.error(f"Error in predict_and_act: {e}")

def handle_attack(src_ip, prediction_prob):
    priority = device_priorities.get(src_ip, 'low')

    if priority == 'high':
        logging.warning(f"High-priority device {src_ip} detected as attack with probability {prediction_prob}. Not blocking.")
        # Implement throttling or alerting instead of blocking
        throttle_ip(src_ip)
    else:
        logging.warning(f"Attack detected from {src_ip} with probability {prediction_prob}. Blocking IP.")
        block_ip(src_ip)

def handle_normal(src_ip, prediction_prob):
    logging.info(f"Normal traffic from {src_ip} with probability {prediction_prob}")

def block_ip(ip_address):
    # Check if IP is already blocked
    result = subprocess.run(['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        # IP is not blocked, so block it
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        print(f"Blocked IP: {ip_address}")
    else:
        print(f"IP {ip_address} is already blocked.")

def throttle_ip(ip_address):
    # Implement throttling logic here (e.g., using tc)
    print(f"Throttling IP: {ip_address}")
    # Example code to limit bandwidth (requires root privileges)
    # os.system(f'sudo tc qdisc add dev eth0 root handle 1: htb default 12')
    # os.system(f'sudo tc class add dev eth0 parent 1: classid 1:1 htb rate 1mbit')
    # os.system(f'sudo tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src {ip_address} flowid 1:1')

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            predict_and_act(packet)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

if __name__ == "__main__":
    # Start sniffing packets
    print("Starting IDS...")
    sniff(prn=packet_callback, store=False)