# Spoofers
This is collection of spoofing tools . This repository basically consisting of layer 2 and layer 3  spoofing tools. The ARP spoofer here basically poisons the Address Resolution protocol at layer 2 which is data link layer in OSI model. And The DNS spoofer poisons the dns records present in /etc/hosts file present in linux systems. These spoofing Tools are made for linux systems.


## Features
This collection is basically designed to perform  man in the middle attacks to pentest networks and identify loopholes in them.

## Requirements
- Python 3
- pip package manager
- Additional Python packages:
  - scapy
  - os
  - argparse
  - time
  - winreg (specifically for windows systems)
  - netfilterqueue
## Installation

Clone the repository:

   git clone https://github.com/grayshader3020/Spoofers
   
   cd Spoofers
   
   ./requirement.sh
   
   sudo python3 arp_spoofer.py
   sudo python3 dns_spoofer.py

Note that to start dns spoofing we have to run arp spoofing first 

**Note: This project is in its earlier stages and may contain bugs. 
Please use it with caution and report any issues you encounter on [GitHub](https://github.com/grayshader3020/Spoofers). 
Your feedback and contributions are highly appreciated!**

