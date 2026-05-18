import socket


def udp_server():
    IP = "127.0.0.1"
    PORT = 5005

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((IP, PORT))
    print(f"UDP listens at {IP}:{PORT}...")

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"Received from {addr}: {data.decode('utf-8')}")

            sock.sendto(b"Message received!", addr)
    except KeyboardInterrupt:
        pass
    finally:
        # 6. Закриваємо сокет
        sock.close()
        print("\nSocket closed.")


if __name__ == "__main__":
    udp_server()