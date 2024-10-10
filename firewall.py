import subprocess
from scapy.all import sniff
import logging

# Set up logging
logging.basicConfig(filename='firewall.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s', 
                    datefmt='%Y-%m-%d %H:%M:%S')

# Function to block an IP address using PowerShell
def block_ip(ip_address):
    command = f'New-NetFirewallRule -DisplayName "Block {ip_address}" -Direction Inbound -Action Block -RemoteAddress {ip_address}'
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Successfully blocked IP: {ip_address}")
            print(f"Blocked IP: {ip_address}")
        else:
            logging.error(f"Failed to block IP: {ip_address}. Error: {result.stderr}")
    except Exception as e:
        logging.error(f"Error while blocking IP {ip_address}: {e}")

# Callback function for packet sniffing
def packet_callback(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        logging.info(f"Packet captured from {src_ip}: {packet.summary()}")
        print(packet.summary())  # Display the packet summary

        # Check if the packet's IP is suspicious and block it
        if src_ip == "192.168.1.100":  # Example of blocking a specific IP
            block_ip(src_ip)

# Start sniffing packets
def start_sniffing():
    logging.info("Starting packet capture...")
    print("Starting packet capture...")
    try:
        sniff(prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"Error during packet sniffing: {e}")

# Run the sniffing function
start_sniffing()


# logging, error handling, and IP blocking functionality all in one