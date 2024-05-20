from scapy.all import *
from collections import defaultdict
import time

# Dictionary to track packet counts per IP address
packet_count = defaultdict(int)
# Set a threshold for detecting excessive packets from a single IP
PACKET_THRESHOLD = 100
# Set a threshold time window (in seconds) for packet counting
TIME_WINDOW = 60

# Dictionary to track the last time we checked for excessive packets
last_check_time = defaultdict(float)

# Function to handle each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Increment the packet count for the source IP
        packet_count[ip_src] += 1

        # Get the current time
        current_time = time.time()

        # Check for excessive packet sending
        if current_time - last_check_time[ip_src] > TIME_WINDOW:
            if packet_count[ip_src] > PACKET_THRESHOLD:
                print(f"Potential malicious activity detected from IP: {ip_src}")
                print(f"Packet count: {packet_count[ip_src]} in the last {TIME_WINDOW} seconds")
            # Reset the count and time
            packet_count[ip_src] = 0
            last_check_time[ip_src] = current_time

        # Check for unusual port access
        if TCP in packet:
            dport = packet[TCP].dport
            common_ports = [80, 443, 22, 21, 25, 53]
            if dport not in common_ports:
                print(f"Unusual port access detected from IP: {ip_src} to port: {dport}")

        # Check for IP spoofing
        if Ether in packet:
            mac_src = packet[Ether].src
            if ip_src != mac_src:
                print(f"IP spoofing detected: IP {ip_src} is associated with MAC {mac_src}")

# Start sniffing packets on the network interface (e.g., 'wlan0')
sniff(iface="wlan0", prn=packet_callback, store=0)
