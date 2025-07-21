from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Other"
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = "-"
            dst_port = "-"

        print(f"[{protocol}] {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

def start_sniffing(packet_count=50):
    print(f"Starting packet capture for {packet_count} packets...")
    sniff(prn=packet_callback, count=packet_count)
    print("Packet capture finished.")

if __name__ == "__main__":
    start_sniffing()
