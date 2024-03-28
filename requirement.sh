#!/bin/bash

# Install required utilities
echo "Installing utilities..."
sudo apt-get update
sudo apt-get install -y python2
sudo apt-get install -y python3
sudo apt-get install -y update
sudo apt-get install -y upgrade 
sudo apt-get install python3-pip

echo "Utility installation completed."

# Install required dependencies
echo "Installing dependencies..."

pip install scapy
pip install os
pip install argparse
pip install  time
pip install winreg 
pip install netfilterqueue


echo "Dependency installation completed."
