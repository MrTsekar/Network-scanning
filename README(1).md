# Network Scanner

## Introduction

The Network Scanner is a Python script that scans a specified IP range for active devices on the network. It uses ARP requests to discover devices and retrieves their MAC addresses. Additionally, it can query an external API to provide vendor information based on the MAC address. The script also detects and displays the operating system of each scanned device using the `nmap` library.

## Features

- Scans a specified IP range for active devices.
- Retrieves the IP and MAC addresses of detected devices.
- Optionally fetches vendor information based on MAC addresses using an external API.
- Detects and displays the operating system of each device.
- Simple command-line interface for ease of use.

## Requirements

To run this script, you need the following:

- Python 3.x
- The `scapy` library for packet manipulation.
- The `requests` library for making HTTP requests.
- The `python-nmap` library for OS detection.

### Installation

1. **Install Python**: Make sure you have Python 3 installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

2. **Install Required Libraries**: You can install the required libraries using pip. Open your terminal or command prompt and run:

### bash
   pip install scapy requests python-nmap

### Usage
python network_scanner.py -t <target_ip_range> [-v]
