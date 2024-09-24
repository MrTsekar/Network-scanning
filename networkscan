from scapy.all import *
import argparse
import requests
import nmap

def scan_network(target_ip):
    arp_request = ARP(pdst=target_ip)
    
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    arp_broadcast = broadcast_frame / arp_request
    
    answered_list = srp(arp_broadcast, timeout=1, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def get_mac_vendor(mac_address):
    url = f"https://api.maclookup.app/v2/macs/{mac_address}"
    response = requests.get(url)
    data = response.json()
    vendor = data.get("vendor", "Unknown")
    return vendor

def get_os_info(ip):
    
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')  
    
    if 'osclass' in nm[ip] and nm[ip]['osclass']:
        os_info = nm[ip]['osclass'][0]['osfamily']
        return os_info
    elif 'osmatch' in nm[ip] and nm[ip]['osmatch']:
        os_info = nm[ip]['osmatch'][0]['name']
        return os_info
    
    return "Unknown"  # Default return if no OS information is found

if __name__ == "__main__":
   
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP or IP range")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display vendor information")
    args = parser.parse_args()

    if args.target:
        target_ip = args.target
    else:
        target_ip = "192.168.1.0/24"  

    scan_results = scan_network(target_ip)

    print("IP\t\tMAC Address\tVendor\t\tOS")
    print("-------------------------------------------------------------------")
    
    for client in scan_results:
        mac_address = client["mac"]
        if args.verbose:
            vendor = get_mac_vendor(mac_address)
        else:
            vendor = ""
        
        os_info = get_os_info(client["ip"])  
        
        print(f"{client['ip']}\t{mac_address}\t{vendor}\t{os_info}")
