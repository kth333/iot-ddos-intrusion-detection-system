import numpy as np
import pandas as pd
from tensorflow import keras
from scapy.all import sniff, IP, TCP, UDP
import joblib
import logging
import subprocess
import re
import time
from logging.handlers import RotatingFileHandler

# Set up logging with rotation
handler = RotatingFileHandler('/logs/ids.log', maxBytes=5*1024*1024, backupCount=3)  # 5MB per file, 3 backups
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Add handler to the root logger
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

# Example log to ensure it's working
logging.info("Logging initialized and working in real-time.")

# Load the trained model
model = keras.models.load_model('/app/models/ddos_detection_model.keras')

# Load preprocessing objects
ohe = joblib.load('/app/models/ohe.joblib')  # OneHotEncoder used during training
scaler = joblib.load('/app/models/scaler.joblib')  # StandardScaler used during training

# Device priority mapping (optional, modify as needed)
device_priorities = {
    '192.168.1.2': 'high',
    '192.168.1.3': 'medium',
}

# Preprocessing features function
def preprocess_features(features, ohe, scaler):
    df = pd.DataFrame([features])

    # Categorical and numerical columns based on the dataset used for training
    categorical_cols = ['proto', 'state_number']
    numerical_cols = ['stddev', 'N_IN_Conn_P_SrcIP', 'min', 'mean', 
                      'N_IN_Conn_P_DstIP', 'drate', 'srate', 'max', 'seq']

    # Ensure all expected columns are present
    for col in categorical_cols + numerical_cols:
        if col not in df.columns:
            df[col] = 0  # Add default values if missing

    # Encode categorical variables
    X_encoded = ohe.transform(df[categorical_cols])

    # Scale numerical features
    X_scaled = scaler.transform(df[numerical_cols])

    # Combine features
    X_preprocessed = np.hstack([X_scaled, X_encoded])

    return X_preprocessed

# Extract features from the packet
def extract_features(packet):
    features = {}

    # Protocol
    if packet.haslayer(TCP):
        features['proto'] = 'tcp'
        features['sport'] = packet[TCP].sport
        features['dport'] = packet[TCP].dport
        features['seq'] = packet[TCP].seq
    elif packet.haslayer(UDP):
        features['proto'] = 'udp'
        features['sport'] = packet[UDP].sport
        features['dport'] = packet[UDP].dport
        features['seq'] = 0
    else:
        features['proto'] = 'other'
        features['sport'] = 0
        features['dport'] = 0
        features['seq'] = 0

    # Source and Destination IPs
    features['saddr'] = packet[IP].src if packet.haslayer(IP) else '0.0.0.0'
    features['daddr'] = packet[IP].dst if packet.haslayer(IP) else '0.0.0.0'

    # Packet length
    features['length'] = len(packet)

    # Additional derived features
    features['stddev'] = 0.0
    features['N_IN_Conn_P_SrcIP'] = 0
    features['min'] = 0
    features['state_number'] = 1  # Ensure this is included
    features['mean'] = features['length']
    features['N_IN_Conn_P_DstIP'] = 0
    features['drate'] = 0
    features['srate'] = 0
    features['max'] = features['length']

    return features

# Prediction and action function
def predict_and_act(packet):
    try:
        features = extract_features(packet)
        saddr = features.get('saddr', '0.0.0.0')  # Use 'saddr' from the dataset

        # Preprocess features (pass ohe and scaler)
        X_preprocessed = preprocess_features(features, ohe, scaler)

        # Predict
        prediction_prob = model.predict(X_preprocessed)[0][0]
        prediction = int(prediction_prob > 0.5)

        if prediction == 1:
            handle_attack(saddr, prediction_prob)
        else:
            handle_normal(saddr, prediction_prob)
    except Exception as e:
        logging.error(f"Error in predict_and_act: {e}")

# Handle attack
def handle_attack(src_ip, prediction_prob):
    priority = device_priorities.get(src_ip, 'low')

    if priority == 'high':
        logging.warning(f"High-priority device {src_ip} detected as attack with probability {prediction_prob}. Not blocking.")
        throttle_ip(src_ip)
    else:
        logging.warning(f"Attack detected from {src_ip} with probability {prediction_prob}. Blocking IP.")
        block_ip(src_ip)

# Handle normal traffic
def handle_normal(src_ip, prediction_prob):
    logging.info(f"Normal traffic from {src_ip} with probability {prediction_prob}")

# Block IP using iptables
def block_ip(ip_address):
    # Check if IP is already blocked
    result = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        # IP is not blocked, so block it
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        logging.info(f"Blocked IP: {ip_address}")
    else:
        logging.info(f"IP {ip_address} is already blocked.")

# Throttle IP (implement if needed)
def throttle_ip(ip_address):
    logging.info(f"Throttling IP: {ip_address}")

# Callback function for packet sniffing
def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            predict_and_act(packet)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Detect Docker bridge interface
def get_docker_bridge_interface():
    for attempt in range(5):
        ifconfig_output = subprocess.check_output(['ifconfig']).decode()
        logging.info(f"Current network configuration:\n{ifconfig_output}")

        interface_pattern = re.compile(r'(br-\w+)')
        match = interface_pattern.search(ifconfig_output)

        if match:
            logging.info(f"Detected Docker bridge interface: {match.group(1)}")
            return match.group(1)
        else:
            logging.warning(f"Docker bridge interface not found, attempt {attempt + 1}/5. Retrying in 3 seconds...")
            time.sleep(3)

    raise Exception("Docker bridge interface not found after multiple retries")

if __name__ == "__main__":
    try:
        logging.info("Waiting 10 seconds before starting IDS...")
        time.sleep(10)
        docker_interface = get_docker_bridge_interface()
        logging.info(f"Starting packet sniffing on {docker_interface}...")
        sniff(iface=docker_interface, prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"Error: {e}")