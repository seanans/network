import socket


def udp_client():
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 5005

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    message = "Wazzup!"

    try:
        sock.sendto(message.encode('utf-8'), (TARGET_IP, TARGET_PORT))
        print(f"Sent: {message}")

        data, server = sock.recvfrom(1024)
        print(f"Servers response: {data.decode('utf-8')}")
    finally:
        sock.close()


if __name__ == "__main__":
    udp_client()