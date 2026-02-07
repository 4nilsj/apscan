import socket
import sys

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

ports = [8081, 5174]
for p in ports:
    if check_port(p):
        print(f"Port {p} is OPEN")
    else:
        print(f"Port {p} is CLOSED")
