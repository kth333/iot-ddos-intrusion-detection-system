import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import joblib
import logging
import subprocess
import re
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Set up logging with rotation
handler = RotatingFileHandler('/logs/ids.log', maxBytes=5*1024*1024, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logging.info("Logging initialized and working in real-time.")

# Load the trained model and feature list
model, feature_columns = joblib.load('/app/models/ddos_detector_model_with_features.joblib')

# Device priority mapping (optional)
device_priorities = {'192.168.1.2': 'high', '192.168.1.3': 'medium'}

# Track flow information across packets
flows = {}

def extract_features(packet):
    features = {col: 0 for col in feature_columns}
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        features['src_ip'] = src_ip
        src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
        dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
        flow_key = (src_ip, dst_ip, src_port, dst_port)
        timestamp = datetime.now()
        
        # Initialize or update flow
        if flow_key not in flows:
            flows[flow_key] = {
                'start_time': timestamp,
                'packet_lengths': [],
                'timestamps': [],
                'total_fwd_packets': 0,
                'total_bwd_packets': 0,
                'total_length_fwd': 0,
                'total_length_bwd': 0
            }
        
        flow = flows[flow_key]
        flow['timestamps'].append(timestamp)
        packet_len = len(packet)
        
        # Direction-specific counts and lengths
        if packet[IP].src == src_ip:
            flow['total_fwd_packets'] += 1
            flow['total_length_fwd'] += packet_len
            features['Total Fwd Packets'] = flow['total_fwd_packets']
            features['Total Length of Fwd Packets'] = flow['total_length_fwd']
        else:
            flow['total_bwd_packets'] += 1
            flow['total_length_bwd'] += packet_len
            features['Total Backward Packets'] = flow['total_bwd_packets']
            features['Total Length of Bwd Packets'] = flow['total_length_bwd']
        
        # Packet length statistics
        flow['packet_lengths'].append(packet_len)
        features['Packet Length Mean'] = np.mean(flow['packet_lengths'])
        features['Packet Length Std'] = np.std(flow['packet_lengths'])
        features['Packet Length Variance'] = np.var(flow['packet_lengths'])
        features['Max Packet Length'] = np.max(flow['packet_lengths'])
        features['Min Packet Length'] = np.min(flow['packet_lengths'])
        
        # Flow duration and rate features
        duration = (timestamp - flow['start_time']).total_seconds()
        features['Flow Duration'] = duration
        features['Flow Bytes/s'] = (flow['total_length_fwd'] + flow['total_length_bwd']) / duration if duration > 0 else 0
        features['Flow Packets/s'] = (flow['total_fwd_packets'] + flow['total_bwd_packets']) / duration if duration > 0 else 0
        
        # Inter-arrival times (IAT)
        if len(flow['timestamps']) > 1:
            iats = [(flow['timestamps'][i] - flow['timestamps'][i-1]).total_seconds() for i in range(1, len(flow['timestamps']))]
            features['Flow IAT Mean'] = np.mean(iats)
            features['Flow IAT Std'] = np.std(iats)
            features['Flow IAT Max'] = np.max(iats)
            features['Flow IAT Min'] = np.min(iats)
    
    # TCP flags
    if packet.haslayer(TCP):
        features['FIN Flag Count'] = 1 if packet[TCP].flags & 0x01 else 0
        features['SYN Flag Count'] = 1 if packet[TCP].flags & 0x02 else 0
        features['RST Flag Count'] = 1 if packet[TCP].flags & 0x04 else 0
        features['PSH Flag Count'] = 1 if packet[TCP].flags & 0x08 else 0
        features['ACK Flag Count'] = 1 if packet[TCP].flags & 0x10 else 0
        features['URG Flag Count'] = 1 if packet[TCP].flags & 0x20 else 0
    
    return features

def preprocess_features(features):
    df = pd.DataFrame([features])
    df = df[feature_columns]
    return df

def predict_and_act(packet):
    try:
        features = extract_features(packet)
        src_ip = features.get('src_ip', '0.0.0.0')
        X_preprocessed = preprocess_features(features)
        
        prediction = model.predict(X_preprocessed)[0]

        if prediction == 1:
            handle_attack(src_ip)
        else:
            handle_normal(src_ip)
    except Exception as e:
        logging.error(f"Error in predict_and_act: {e}")

# Handle attack
def handle_attack(src_ip):
    priority = device_priorities.get(src_ip, 'low')

    if priority == 'high':
        logging.warning(f"High-priority device {src_ip} detected as attack. Not blocking.")
    else:
        logging.warning(f"Attack detected from {src_ip}. Blocking IP.")
        block_ip(src_ip)

def handle_normal(src_ip):
    logging.info(f"Normal traffic from {src_ip}")

def block_ip(ip_address):
    result = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        logging.info(f"Blocked IP: {ip_address}")
    else:
        logging.info(f"IP {ip_address} is already blocked.")

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
        logging.info("Waiting 5 seconds before starting IDS...")
        time.sleep(5)
        docker_interface = get_docker_bridge_interface()
        logging.info(f"Starting packet sniffing on {docker_interface}...")
        sniff(iface=docker_interface, prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"Error: {e}")