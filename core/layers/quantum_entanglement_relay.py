#!/usr/bin/env python3
# SHENRON: Quantum Entanglement Relay — threaded socket relay for covert channel bridging
import socket
import threading

def entangle(port=4242):
    relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_socket.bind(("127.0.0.1", port))
    relay_socket.listen(5)
    print(f"[+] Quantum entanglement relay opened on port {port}")

    def relay(conn):
        data = conn.recv(4096)
        print(f"[~] Quantum packet received: {len(data)} bytes")
        conn.close()

    while True:
        conn, addr = relay_socket.accept()
        threading.Thread(target=relay, args=(conn,)).start()

if __name__ == "__main__":
    entangle()
