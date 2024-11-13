from scapy.all import *

target_ip = "129.113.6.108" 

def send_large_icmp_packets(target_ip, count=5):
    for i in range(count):
        packet = IP(dst=target_ip) / ICMP(type=8) / ("X" * 65000)
        print(f"Sending packet {i+1}: {packet.summary()} (Length: {len(packet)})")  
        send(packet)

if __name__ == "__main__":
    send_large_icmp_packets(target_ip)
