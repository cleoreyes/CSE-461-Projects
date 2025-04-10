import socket
import struct
# import  

SERVER_ADDR = 'attu2.cs.washington.edu'
UDP_PORT = 12235
TIMEOUT = 3
RETRANSMIT_INTERVAL = 0.5
STUDENT_ID_TAIL = 338  # TODO: replace with last 3 digits of your student ID

def make_header(payload_len, psecret, step, student_id_tail=STUDENT_ID_TAIL):
    return struct.pack('!I I H H', payload_len, psecret, step, student_id_tail)

def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        data += chunk
    return data

def stage_a():
    print("---- Starting Stage A ----")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Sending to {SERVER_ADDR}:{UDP_PORT}")
    sock.settimeout(TIMEOUT)

    payload = b'hello world\0'
    header = make_header(len(payload), 0, 1)
    packet = header + payload
    print(f"Sending packet: {packet}")

    sock.sendto(packet, (SERVER_ADDR, UDP_PORT))
    print("Sent 'hello world'")

    data, _ = sock.recvfrom(1024)
    if len(data) < 16:
        raise Exception("Stage A response too short")

    payload = data[12:]  # Skip header
    num, length, udp_port, secretA = struct.unpack('!IIII', payload)
    print(f"Received: num={num}, len={length}, udp_port={udp_port}, secretA={secretA}")

    return num, length, udp_port, secretA

def main():
    num, length, udp_port, secretA = stage_a()

    print("\n[✓] Protocol complete!")

if __name__ == "__main__":
    main()
