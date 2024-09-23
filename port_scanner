import socket
import argparse
import logging
import time

# Configure logging
logging.basicConfig(
    filename='port_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def scan_open_ports(target_ip, start_port, end_port):
    """Scan for open TCP ports on a given IP address."""
    open_ports = []
    
    for port in range(start_port, end_port + 1):  # Scan specified port range
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        
        try:
            result = sock.connect_ex((target_ip, port))  # Try to connect to the port
            if result == 0:
                open_ports.append(port)  # Port is open
                logging.info(f"Port {port} is open on {target_ip}")
            else:
                logging.info(f"Port {port} is closed on {target_ip}")
        except Exception as e:
            logging.error(f"Error connecting to {target_ip}:{port} - {e}")
        finally:
            sock.close()  # Ensure the socket is closed

    return open_ports

if __name__ == "__main__":
    # Create an argument parser
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("target", help="Target IP or hostname to scan")
    parser.add_argument("--start", "-s", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", "-e", type=int, default=1024, help="End port (default: 1024)")
    
    args = parser.parse_args()
    
    target_ip = args.target
    start_port = args.start
    end_port = args.end
    
    # Start timing the scan
    start_time = time.time()
    
    # Perform port scanning
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    open_ports = scan_open_ports(target_ip, start_port, end_port)
    
    # Calculate runtime
    end_time = time.time()
    runtime = end_time - start_time
    
    # Print results
    print(f"\nScan completed in {runtime:.2f} seconds.")
    print(f"Open ports on {target_ip}:")
    
    if open_ports:
        print(", ".join(map(str, open_ports)))
    else:
        print("No open ports found.")
    # example python port_scanner.py 192.168.1.1 --start 20 --end 80
