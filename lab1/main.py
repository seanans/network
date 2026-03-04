import urllib.request
import socket
import struct

def get_public_ip():
    req = urllib.request.Request("https://api.ipify.org", headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        return response.read().decode('utf-8').strip()


# Сonvert an IP string to a 32-bit unsigned integer
def ip_to_int(ip_str):
    packed_ip = socket.inet_aton(ip_str)
    # "!I" means Network byte order (big-endian), unsigned integer
    return struct.unpack("!I", packed_ip)[0]


def main():
    print("Stage 1: Getting public IP address...")
    try:
        my_ip = get_public_ip()
        print(f"[*] My public IP: {my_ip}")
    except Exception as e:
        print(f"[!] Failed to get IP: {e}")
        return

    print("\nStage 2: Downloading RIPE delegation file via FTP...")

    url = "ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"

    try:
        with urllib.request.urlopen(url) as response:
            file_content = response.read().decode('utf-8').splitlines()
            print(f"[*] Download complete! Total lines to analyze: {len(file_content)}")
    except Exception as e:
        print(f"[!] Failed to download FTP file: {e}")
        return

    print("\nSearching for the matching delegation...\n")

    # Convert our IP to a 32-bit integer for bitwise operations
    my_ip_int = ip_to_int(my_ip)
    found = False

    for line in file_content:
        if line.startswith('#') or not line:
            continue

        parts = line.split('|')

        # Only IPv4 records (format: registry|cc|type|start|value|date|status)
        if len(parts) >= 7 and parts[2] == 'ipv4':
            net_ip_str = parts[3]
            count = int(parts[4])

            # MATH EXPLANATION FOR THE MASK:
            # 'count' is the number of IP addresses (e.g., 8192).
            # The maximum host value in this subnet is (count - 1), e.g., 8191.
            # In binary, 8191 is a sequence of 1s at the end (000...001111111111111).
            # To get the subnet mask, we invert these bits.
            # XORing (^) with 0xFFFFFFFF (32 ones) perfectly flips the bits.
            mask = 0xFFFFFFFF ^ (count - 1)

            net_ip_int = ip_to_int(net_ip_str)

            # The core lab condition: (IP AND MASK) == (NETADDR AND MASK)
            if (my_ip_int & mask) == (net_ip_int & mask):
                print("-" * 75)
                print(">>> MATCH FOUND! <<<")
                print(f"Delegation string : {line}")

                # Bonus: decoding the mask to readable format for the defense
                packed_mask = struct.pack("!I", mask)
                mask_str = socket.inet_ntoa(packed_mask)
                print(f"Calculated Mask   : {mask_str}")
                print("-" * 75)

                found = True
                break

    if not found:
        print("[!] No matching delegation found in the RIPE file.")


if __name__ == "__main__":
    main()
