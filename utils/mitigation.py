import subprocess

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