import socket
import struct
import os
from time import perf_counter

class ping:
    def __init__(self, socket):
        self.socket = socket

    def checksum(self, source_string: bytes) -> int:
        """
        Calculate the checksum of the given data.
        """
        sum = 0
        countTo = (len(source_string) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = source_string[count + 1] * 256 + source_string[count]
            sum = sum + thisVal
            sum = sum & 0xffffffff
            count = count + 2

        if countTo < len(source_string):
            sum = sum + source_string[len(source_string) - 1]
            sum = sum & 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    """
    @:param 1 or 0, start timer, stop timer
    """
    def timer(self, start_stop: int, start_time=None):
        if start_stop == 1:
            start = perf_counter()
            return start

        end = perf_counter()
        if start_time:
            return end - start_time
        else:
            return "there was an error in timing the ping"

    def process_data(self, data: bytes, start_time: int):
        ip_header = data[:20]

        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        icmp_header = data[iph_length:iph_length + 8]
        icmph = struct.unpack('!BBHHH', icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        time = self.timer(0, start_time)

        self.print_unpacked_info(iph_length, protocol, s_addr, d_addr, icmp_type, code, time)

    def print_unpacked_info(self, ip_length, protocol, s_addr, d_addr, icmp_type, imcp_code, icmp_ping):
        print(f"ip packet: legnth: {ip_length}, protocol: {protocol}, source: {s_addr}, destination: {d_addr}")

        if type(icmp_ping) == float: #timer has worked and not errored out
            icmp_ping = icmp_ping * 1000
            print(f"icmp packet: type: {icmp_type}, code: {imcp_code}, ping: {icmp_ping}ms")

        else: #isnt a int so must be error string
            print(f"icmp packet: type: {icmp_type}, code: {imcp_code}, ping: {icmp_ping}")

    def pack_icmp_packet(self, identifier: int, sequence_number: int, payload: bytes) -> bytes:
        icmp_type = 8  # Echo Request
        icmp_code = 0
        checksum_placeholder = 0

        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_placeholder, identifier, sequence_number)

        packet_placeholder = header + payload

        checksum = self.checksum(packet_placeholder)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence_number)

        return header + payload


    def listen_for_reply(self, start_time: int):
        response, addr = self.socket.recvfrom(1024)
        self.process_data(response, start_time)

    def doPing(self, ip: str, port: int) -> None:
        packet = self.pack_icmp_packet(5, 1, b"Hello, World!")
        self.socket.sendto(packet, (ip, port))
        start_time = self.timer(1)
        self.listen_for_reply(start_time)


    def is_valid_ip(self, ip: str):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


    def start(self):
        while True:
            try:
                addr = input("address to ping(ip:port):")
                ip, port = addr.split(":")
                port = int(port)
                if self.is_valid_ip(ip) and (0 <= port <= 65535): #is it a valid ip and port
                    self.doPing(ip=ip, port=port)
                    break

                elif not self.is_valid_ip(ip): #is it a invalid ip
                    print("not a valid ip address")

                elif not (0 <= port <= 65535): #is it a inavlid port number
                    print("not a valid port number")

            except ValueError:
                print("Not in correct format")

ping = ping(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))
ping.start()