import struct

class Packet:
    HEADER_FORMAT = '!IIHH'
    HEADER_SIZE = 12

    # initialize mock header + payload with class
    # assumes that the payload is already processed in byte form and ready to send
    def __init__(self, payload_len: int, psecret: int, step: int, payload):
        self.payload_len = payload_len
        self.psecret = psecret
        self.step = step
        self.id_num = 696
        self.payload = payload


    # processes the packet object into sendable form
    # adds header and padding
    def wrap_payload(self) -> bytes:
        header = struct.pack(
            self.HEADER_FORMAT,
            self.payload_len,
            self.psecret,
            self.step,
            self.id_num
        )

        packet = header + self.payload

        if len(packet) % 4 == 0:
            padding = 0
        else:
            padding = 4 - len(packet) % 4

        packet += b'\x00' * padding
        
        return packet


    # returns the payload in bytes from a packet
    @staticmethod
    def extract_payload(packet: bytes) -> bytes:
        header = struct.unpack(Packet.HEADER_FORMAT, packet[:Packet.HEADER_SIZE])

        payload_start = Packet.HEADER_SIZE
        payload_len = header[0]

        return packet[payload_start:payload_start + payload_len]
        



    

