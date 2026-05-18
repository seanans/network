import socket
import time


def run_speed_client():
    HOST = '192.168.50.190'
    PORT = 65432
    TEST_DURATION = 10

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f"Connecting to {HOST}:{PORT}...")

    client_socket.connect((HOST, PORT))

    buffer_size = 65536
    chunk = b'x' * buffer_size

    print(f"Starting upload speed test for {TEST_DURATION} seconds...")
    start_time = time.time()

    try:
        while time.time() - start_time < TEST_DURATION:
            client_socket.sendall(chunk)
    finally:
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()
        print("Speed test finished. Connection closed gracefully.")


if __name__ == "__main__":
    run_speed_client()