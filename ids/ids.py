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

# Track flow information across packets and blocked IPs
flows = {}
blocked_ips = set()

# Extract features from packet
def extract_features(packet):
    features = {col: 0 for col in feature_columns}
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.now()
        packet_len = len(packet)
        
        # Initialize flow key and get TCP/UDP info
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = 0
        else:
            return features  # Skip non-TCP/UDP packets

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        if flow_key not in flows:
            flows[flow_key] = {
                'start_time': timestamp,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'fin_flags': 0,
                'syn_flags': 0,
                'rst_flags': 0,
                'psh_flags': 0,
                'ack_flags': 0,
                'urg_flags': 0
            }

        flow = flows[flow_key]
        
        # Update flow stats based on direction
        is_forward = (packet[IP].src == src_ip)
        if is_forward:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_len
            flow['fwd_packet_lengths'].append(packet_len)
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_len
            flow['bwd_packet_lengths'].append(packet_len)

        # TCP flags update
        if packet.haslayer(TCP):
            flags = int(packet[TCP].flags)
            flow['fin_flags'] += (flags & 0x01)
            flow['syn_flags'] += (flags & 0x02)
            flow['rst_flags'] += (flags & 0x04)
            flow['psh_flags'] += (flags & 0x08)
            flow['ack_flags'] += (flags & 0x10)
            flow['urg_flags'] += (flags & 0x20)

        # Calculate feature values
        duration = (timestamp - flow['start_time']).total_seconds()
        features['Destination Port'] = dst_port
        features['Flow Duration'] = duration
        features['Total Fwd Packets'] = flow['fwd_packets']
        features['Total Backward Packets'] = flow['bwd_packets']
        features['Total Length of Fwd Packets'] = flow['fwd_bytes']
        features['Total Length of Bwd Packets'] = flow['bwd_bytes']
        features['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration if duration > 0 else 0
        features['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration if duration > 0 else 0
        
        # Forward packet length statistics
        if flow['fwd_packet_lengths']:
            features['Fwd Packet Length Max'] = max(flow['fwd_packet_lengths'])
            features['Fwd Packet Length Min'] = min(flow['fwd_packet_lengths'])
            features['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_lengths'])
            features['Fwd Packet Length Std'] = np.std(flow['fwd_packet_lengths'])

        # Backward packet length statistics
        if flow['bwd_packet_lengths']:
            features['Bwd Packet Length Max'] = max(flow['bwd_packet_lengths'])
            features['Bwd Packet Length Min'] = min(flow['bwd_packet_lengths'])
            features['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_lengths'])
            features['Bwd Packet Length Std'] = np.std(flow['bwd_packet_lengths'])

        # TCP Flag counts
        features['FIN Flag Count'] = flow['fin_flags']
        features['SYN Flag Count'] = flow['syn_flags']
        features['RST Flag Count'] = flow['rst_flags']
        features['PSH Flag Count'] = flow['psh_flags']
        features['ACK Flag Count'] = flow['ack_flags']
        features['URG Flag Count'] = flow['urg_flags']

    return features

# Preprocess features for ML model
def preprocess_features(features):
    df = pd.DataFrame([features])
    return df[feature_columns]

# Predict and act on packet based on ML model
def predict_and_act(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in blocked_ips:
                logging.debug(f"Skipping blocked IP: {src_ip}")
                return

            features = extract_features(packet)
            relevant_features = {k: v for k, v in features.items() if k in feature_columns}
            logging.info(f"Relevant features: {relevant_features}")
            
            df = preprocess_features(features)
            prediction_prob = model.predict_proba(df)[0][1]  # Get probability for 'DDoS' class
            prediction = model.predict(df)[0]

            logging.info(f"Prediction probability for 'DDoS': {prediction_prob}")
            if prediction == 1:
                logging.warning(f"ML model detected attack from {src_ip} with probability {prediction_prob}")
                handle_attack(src_ip)
            else:
                handle_normal(src_ip)
    except Exception as e:
        logging.error(f"Error in predict_and_act: {e}")

# Handle normal traffic based on IP address
def handle_normal(src_ip):
    logging.info(f"Normal traffic from {src_ip}")

# Handle attack based on IP address
def handle_attack(ip_address):
    blocked_ips.add(ip_address)
    commands = [
        ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
        ['iptables', '-D', 'FORWARD', '-s', ip_address, '-j', 'DROP'],
        ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'],
        ['iptables', '-I', 'FORWARD', '1', '-s', ip_address, '-j', 'DROP']
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, check=False, capture_output=True)
        except Exception as e:
            logging.error(f"Error running command {cmd}: {e}")

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            logging.info(f"Packet received from {src_ip}")
            if src_ip not in blocked_ips:
                predict_and_act(packet)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

#  Detect Docker bridge interface 
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
        docker_interface = get_docker_bridge_interface()
        sniff(iface=docker_interface, prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"Error: {e}")
