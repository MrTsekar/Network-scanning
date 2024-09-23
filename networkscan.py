from scapy.all import *
import argparse

def scan_network(target_ip):
    # Create an ARP packet with the destination IP address
    arp_request = ARP(pdst=target_ip)
    
    # Create an Ethernet frame to broadcast the ARP request
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the ARP request and broadcast frame
    arp_broadcast = broadcast_frame / arp_request
    
    # Send the packet and receive the response
    answered_list = srp(arp_broadcast, timeout=1, verbose=False)[0]
    
    # Process the response and extract the IP and MAC addresses
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def get_mac_vendor(mac_address):
    # Use the MACLookup API to get the vendor information
    url = f"https://api.maclookup.app/v2/macs/{mac_address}"
    response = requests.get(url)
    data = response.json()
    vendor = data.get("vendor", "Unknown")
    return vendor

# Create an argument parser
parser = argparse.ArgumentParser(description="Network Scanner")
parser.add_argument("-t", "--target", dest="target", help="Target IP or IP range")
parser.add_argument("-v", "--verbose", action="store_true", help="Display vendor information")
args = parser.parse_args()

# Check if a target IP or range is provided
if args.target:
    target_ip = args.target
else:
    target_ip = "192.168.1.0/24"  # Default IP range

# Perform network scanning
scan_results = scan_network(target_ip)

# Print the scan results
print("IP\t\tMAC Address\tVendor")
print("-----------------------------------------")
for client in scan_results:
    mac_address = client["mac"]
    if args.verbose:
        vendor = get_mac_vendor(mac_address)
    else:
        vendor = ""
    print(f"{client['ip']}\t{mac_address}\t{vendor}")