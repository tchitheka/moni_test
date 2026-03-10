import pcapy
import struct
import socket
import time
import threading
from collections import defaultdict

INTERFACES = ["wlp0s20f3"]

TCP_TIMEOUT = 3

syn_table = {}
syn_retry = defaultdict(int)

dns_counter = defaultdict(int)

arp_requests = defaultdict(int)

flow_counter = defaultdict(int)

lock = threading.Lock()


def log(msg):
    ts=time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def parse_ip(pkt,offset):

    iph = struct.unpack("!BBHHHBBH4s4s",pkt[offset:offset+20])

    proto=iph[6]

    src=socket.inet_ntoa(iph[8])
    dst=socket.inet_ntoa(iph[9])

    return proto,src,dst


def parse_tcp(pkt,offset):

    tcph=struct.unpack("!HHLLBBHHH",pkt[offset:offset+20])

    sport=tcph[0]
    dport=tcph[1]
    flags=tcph[5]

    return sport,dport,flags


def parse_udp(pkt,offset):

    udph=struct.unpack("!HHHH",pkt[offset:offset+8])

    return udph[0],udph[1]


def parse_dns(pkt,offset):

    dns_offset=offset+8

    dns=struct.unpack("!HHHHHH",pkt[dns_offset:dns_offset+12])

    flags=dns[1]

    rcode=flags & 0xF

    return rcode


def parse_icmp(pkt,offset):

    icmp=struct.unpack("!BBH",pkt[offset:offset+4])

    return icmp[0],icmp[1]


def parse_arp(pkt):

    arp=struct.unpack("!HHBBH6s4s6s4s",pkt[14:42])

    src_ip=socket.inet_ntoa(arp[6])
    dst_ip=socket.inet_ntoa(arp[8])

    return src_ip,dst_ip


def detect_dns(src,dst,rcode):

    if rcode==0:
        log(f"DNS_SUCCESS {src}->{dst}")

    else:
        log(f"DNS_FAILURE rcode={rcode} {src}->{dst}")

    dns_counter[src]+=1

    if dns_counter[src]>50:

        log(f"DNS_QUERY_STORM from {src}")


def detect_tcp(src,dst,dport,flags):

    syn=flags & 2
    ack=flags & 16
    rst=flags & 4

    key=(src,dst,dport)

    if syn and not ack:

        syn_table[key]=time.time()

        syn_retry[key]+=1

        if syn_retry[key]>3:

            log(f"NAT_TABLE_EXHAUSTION suspected {src}->{dst}:{dport}")

    elif syn and ack:

        rev=(dst,src,dport)

        if rev in syn_table:

            del syn_table[rev]

    elif rst:

        log(f"TCP_RESET {src}->{dst}:{dport}")


def detect_icmp(src,dst,type,code):

    if type==3:

        log(f"HOST_UNREACHABLE {src}->{dst}")

    if type==11:

        log(f"ROUTING_LOOP TTL exceeded {src}->{dst}")


def detect_arp(src,dst):

    arp_requests[(src,dst)]+=1

    if arp_requests[(src,dst)]>3:

        log(f"LOCAL_CONNECTIVITY_FAILURE {src} cannot reach {dst}")


def detect_traffic(src):

    flow_counter[src]+=1

    if flow_counter[src]>500:

        log(f"TRAFFIC_DOMINANCE {src} heavy traffic user")


def process(pkt):

    eth_proto=struct.unpack("!H",pkt[12:14])[0]

    if eth_proto==0x0806:

        src,dst=parse_arp(pkt)

        detect_arp(src,dst)

        return

    if eth_proto!=0x0800:
        return

    proto,src,dst=parse_ip(pkt,14)

    detect_traffic(src)

    if proto==1:

        icmp_type,icmp_code=parse_icmp(pkt,34)

        detect_icmp(src,dst,icmp_type,icmp_code)

    if proto==6:

        sport,dport,flags=parse_tcp(pkt,34)

        detect_tcp(src,dst,dport,flags)

    if proto==17:

        sport,dport=parse_udp(pkt,34)

        if sport==53 or dport==53:

            rcode=parse_dns(pkt,34)

            detect_dns(src,dst,rcode)


def capture(iface):

    cap=pcapy.open_live(iface,65536,1,100)

    while True:

        header,pkt=cap.next()

        if pkt:

            process(pkt)


def syn_timeout():

    while True:

        now=time.time()

        expired=[]

        for k,t in syn_table.items():

            if now-t>TCP_TIMEOUT:

                src,dst,port=k

                log(f"TCP_SERVICE_FAILURE {src}->{dst}:{port}")

                expired.append(k)

        for k in expired:

            del syn_table[k]

        time.sleep(1)


def main():

    for iface in INTERFACES:

        t=threading.Thread(target=capture,args=(iface,))
        t.daemon=True
        t.start()

    checker=threading.Thread(target=syn_timeout)
    checker.daemon=True
    checker.start()

    while True:
        time.sleep(1)


if __name__=="__main__":
    main()