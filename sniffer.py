from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Check for specific protocols: TCP, UDP, ICMP
        if packet.haslayer(TCP):
            print(f"[TCP] Source: {ip_src}:{packet[TCP].sport} -> Destination: {ip_dst}:{packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"[UDP] Source: {ip_src}:{packet[UDP].sport} -> Destination: {ip_dst}:{packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"[ICMP] Source: {ip_src} -> Destination: {ip_dst}")
        else:
            print(f"[Other Protocol] Source: {ip_src} -> Destination: {ip_dst} (Protocol: {protocol})")

# Capture packets in real-time
print("Starting network capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)  # prn specifies the callback function, store=False to prevent saving packets
