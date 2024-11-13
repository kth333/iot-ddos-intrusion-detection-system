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

# Detection thresholds
PACKET_THRESHOLD = 10  # Much lower threshold to catch rapid succession
TIME_WINDOW = 0.1      # Shorter time window (100ms) to detect burst traffic

# Track packet counts
packet_counts = {}
blocked_ips = set()

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

def check_rate_limit(src_ip, current_time):
    """
    Check if the source IP has exceeded the rate limit threshold.
    """
    if src_ip in packet_counts:
        elapsed = current_time - packet_counts[src_ip]['last_time']
        packet_counts[src_ip]['count'] += 1

        # Check if threshold exceeded
        if elapsed < TIME_WINDOW and packet_counts[src_ip]['count'] > PACKET_THRESHOLD:
            logging.warning(f"Potential DDoS attack detected from {src_ip} - {packet_counts[src_ip]['count']} packets in {elapsed:.4f}s")
            handle_attack(src_ip)
            return True
            
        # Reset counter if time window expired
        if elapsed > TIME_WINDOW:
            packet_counts[src_ip] = {'count': 1, 'last_time': current_time}
    else:
        packet_counts[src_ip] = {'count': 1, 'last_time': current_time}
    
    return False

def predict_and_act(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            if src_ip in blocked_ips:
                logging.debug(f"Skipping blocked IP: {src_ip}")
                return
            # Add immediate rate check before ML prediction
            if check_rate_limit(src_ip, time.time()):
                return
                
            # features = extract_features(packet)
            # df = preprocess_features(features)
            # prediction = model.predict(df)[0]

            # if prediction == 1:
            #     logging.warning(f"ML model detected attack from {src_ip}")
            #     handle_attack(src_ip)
            #     return
            
            logging.info(f"Normal traffic from {src_ip}")
            
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
    """Block an IP using both iptables and in-memory tracking"""
    try:
        # Add to blocked set
        blocked_ips.add(ip_address)
        
        # More aggressive blocking rules
        commands = [
            # Clear any existing rules for this IP
            ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            ['iptables', '-D', 'FORWARD', '-s', ip_address, '-j', 'DROP'],
            # Add new rules at the start of chains
            ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'],
            ['iptables', '-I', 'FORWARD', '1', '-s', ip_address, '-j', 'DROP'],
            # Block established connections
            ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'DROP']
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, check=False, capture_output=True)
            except Exception as e:
                logging.error(f"Error running command {cmd}: {e}")

        return True
        
    except Exception as e:
        logging.error(f"Failed to block {ip_address}: {e}")
        return False

def packet_callback(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            
            # Skip processing if IP is already blocked
            if src_ip in blocked_ips:
                logging.debug(f"Dropping packet from blocked IP: {src_ip}")
                return
                
            dst_port = packet[TCP].dport
            
            # Focus on SYN packets to MQTT port
            if dst_port == 1883 and packet[TCP].flags & 0x02:  # SYN flag
                logging.debug(f"SYN packet detected: {src_ip} -> port 1883")
                
                current_time = time.time()
                if src_ip not in packet_counts:
                    packet_counts[src_ip] = {'count': 1, 'last_time': current_time}
                else:
                    elapsed = current_time - packet_counts[src_ip]['last_time']
                    packet_counts[src_ip]['count'] += 1
                    
                    # If we see more than 10 SYN packets in 1 second
                    if elapsed <= 1.0 and packet_counts[src_ip]['count'] > 10:
                        logging.warning(f"DDoS Attack detected! {src_ip} sent {packet_counts[src_ip]['count']} SYN packets in {elapsed:.2f} seconds")
                        handle_attack(src_ip)
                        return
                    
                    # Reset counter after 1 second
                    if elapsed > 1.0:
                        packet_counts[src_ip] = {'count': 1, 'last_time': current_time}
            
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