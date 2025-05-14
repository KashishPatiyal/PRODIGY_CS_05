from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Output log file
LOG_FILE = "packet_log.txt"

# Function to write logs
def log_packet(data):
    with open(LOG_FILE, "a") as f:
        f.write(data + "\n")

# Function to process each packet
def packet_handler(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        log_data = f"[{timestamp}] Protocol: {proto}, Source: {src_ip}, Destination: {dst_ip}"

        # Check for TCP
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            payload = bytes(packet[TCP].payload)
            log_data += f", Src Port: {sport}, Dst Port: {dport}, Payload: {payload[:20]}"
        
        # Check for UDP
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            payload = bytes(packet[UDP].payload)
            log_data += f", Src Port: {sport}, Dst Port: {dport}, Payload: {payload[:20]}"

        print(log_data)
        log_packet(log_data)

# Start sniffing (change iface to your network adapter if needed)
print("🟢 Sniffing started... Press Ctrl+C to stop.\n")
sniff(filter="ip", prn=packet_handler, store=False, count=50)


