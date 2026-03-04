import socket
import uuid
import subprocess
import urllib.request
import time


def get_mac_vendor(mac):
    if mac == "Unknown":
        return "-"
    try:
        time.sleep(1)
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            return response.read().decode('utf-8')
    except:
        return "Unknown vendor"


def main():
    print("Starting network scan...\n")

    # 1. Get my IP
    hostname = socket.gethostname()
    my_ip = socket.gethostbyname(hostname)

    # Get my MAC and format it with hyphens
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    my_mac = '-'.join(mac_num[i: i + 2] for i in range(0, 12, 2))

    print(f"PC: IP = {my_ip}, MAC = {my_mac}")

    # 2. Find the router (gateway) IP using the ipconfig command
    gateway_ip = "Unknown"
    ipconfig_out = subprocess.getoutput("ipconfig")

    for line in ipconfig_out.split('\n'):
        if "Default Gateway" in line:
            parts = line.split(':')
            if len(parts) == 2 and parts[1].strip() != "":
                gateway_ip = parts[1].strip()
                break  # Found the gateway, break the loop

    print(f"Router IP: {gateway_ip}")

    # 3. Find the router MAC via the ARP table
    gateway_mac = "Unknown"
    if gateway_ip != "Unknown":
        # Do 1 ping so the router definitely appears in the ARP table
        subprocess.run(["ping", "-n", "1", gateway_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        arp_out = subprocess.getoutput("arp -a")
        for line in arp_out.split('\n'):
            if gateway_ip in line:
                # Split the line into words (IP, MAC, Type)
                words = line.split()
                if len(words) >= 2 and words[0] == gateway_ip:
                    gateway_mac = words[1].upper().replace('-', ':')
                    break

    print(f"Router MAC: {gateway_mac}")
    print("\nQuerying the vendor database...\n")

    # 4. Get the vendors
    my_vendor = get_mac_vendor(my_mac.replace('-', ':'))
    gateway_vendor = get_mac_vendor(gateway_mac)

    # 5. Print the table
    print("-" * 75)
    print(f"{'Role':<15} | {'IP address':<15} | {'MAC address':<20} | {'Vendor'}")
    print("-" * 75)
    print(f"{'My laptop':<15} | {my_ip:<15} | {my_mac.replace('-', ':'):<20} | {my_vendor}")
    print(f"{'Router':<15} | {gateway_ip:<15} | {gateway_mac:<20} | {gateway_vendor}")
    print("-" * 75)


if __name__ == "__main__":
    main()