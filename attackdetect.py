from scapy.all import *
import logging 
import smtplib
import sys

logging.basicConfig(filename='attackdetect.log', level=logging.INFO, format='%(asctime)s %(message)s')

syn_count = {}
packet_count=0
THRESHOLD=100
DDOS_THRESHOLD=1000

def capture_traffic():
	sniff(prn=analyze_packet, store=0)

def analyze_packet(packet):
	if packet.haslayer(TCP):
		detect_syn_flood(packet)
	if packet.haslayer(IP):
		detect_ddos(packet)
	if packet.haslayer(ICMP):
		detect_ping_of_death(packet)

def detect_syn_flood(packet):
	if packet[TCP]. flags == "S":
		src_ip = packet[IP].src
		if src_ip not in syn_count:
			syn_count[src_ip] = 0
		syn_count[src_ip] += 1
		if syn_count[src_ip] > THRESHOLD:
			log_attack(f"SYN FLOOD ATTACK DETECTED FROM IP: {src_ip}")

def detect_ddos(packet):
	global packet_count
	packet_count += 1 
	if packet_count > DDOS_THRESHOLD:
		log_attack("POTENTIAL DDoS ATTACK DETECTED")

def detect_ping_of_death(packet):
	if packet[ICMP].type == 8:
		if len(packet) > 65535:
			log_attack(f"PING OF DEATH DETECTED FROM IP: {packet[IP].src}")

def log_attack(message):
	logging.info(message)
	print(message)
	send_alrt(message)
	sys.exit()

def send_alrt(message):
	server = smtplib.SMTP('smtp.gmail.com', 587)
	server.starttls()
	server.login('pencilcream98@gmail.com', 'Tortotas5')
	server.sendmail('pencilcream09@gmail.com', 'pencilcream98@gmail.com', message)
	server.quit()

if __name__ == "__main__":
	capture_traffic()