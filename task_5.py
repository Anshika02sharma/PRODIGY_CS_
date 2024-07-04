from scapy.all import sniff, IP, Raw

def packet_analysis(packet):
    # Check if packet is IPv4
    if packet.haslayer(IP):
        # Get source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Get protocol
        protocol = packet[IP].proto

        # Check if Raw layer exists
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = b""  # Set payload to an empty byte string if not present

        # Print packet information
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")
        try:
            print(f"Payload: {payload.decode('utf-8', errors='replace')}")
        except UnicodeDecodeError:
            print("Payload: [Non-decodable data]")
        print("--------------------------------")

# Start sniffing
sniff(filter="ip", prn=packet_analysis)
