import socket
import time


def run_speed_server():
    HOST = '0.0.0.0'
    PORT = 65432

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((HOST, PORT))

    server_socket.listen()
    print(f"Speed Test Server listening on {HOST}:{PORT}...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    total_bytes = 0
    start_time = time.time()

    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            total_bytes += len(data)
    finally:
        end_time = time.time()
        duration = end_time - start_time

        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        server_socket.close()

        if duration > 0:
            speed_bps = total_bytes / duration
            speed_mbps = speed_bps / (1024 * 1024)
            print("\n--- Test Results ---")
            print(f"Total data received: {total_bytes} bytes")
            print(f"Time elapsed: {duration:.2f} seconds")
            print(f"Average Speed: {speed_bps:.2f} Bytes/sec ({speed_mbps:.2f} MB/s)")


if __name__ == "__main__":
    run_speed_server()