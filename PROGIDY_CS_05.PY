from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"\nIP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {ip_src}:{tcp_layer.sport} -> {ip_dst}:{tcp_layer.dport}")
            if packet[TCP].payload:
                print(f"Payload: {str(packet[TCP].payload)}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: {ip_src}:{udp_layer.sport} -> {ip_dst}:{udp_layer.dport}")
            if packet[UDP].payload:
                print(f"Payload: {str(packet[UDP].payload)}")
        
        elif packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            print(f"HTTP Request: {http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}")

def main():
    # Use conf.L3socket instead of Layer 2 capture to avoid the winpcap requirement
    conf.L3socket()
    
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()