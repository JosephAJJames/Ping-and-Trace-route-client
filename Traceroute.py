import sys

from ping import Ping
import socket
import struct
import os
from time import perf_counter

class Tracetoute(Ping):
    def __init__(self, sock):
        super().__init__(sock)
        self.socket.settimeout(5)


    def process_data(self, data: bytes, start_time: int, ip: str):
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

        if code == 3: #if the destination is unreachable
            return 3

        if s_addr == ip:
            self.print_unpacked_info(iph_length, protocol, s_addr, d_addr, icmp_type, code, time)
            sys.exit(1)

        self.print_unpacked_info(iph_length, protocol, s_addr, d_addr, icmp_type, code, time)

    def doPing(self, ip: str, port: int) -> int:
        packet = self.pack_icmp_packet(5, 1, b"Hello, World!")
        self.socket.sendto(packet, (ip, port))
        start_time = self.timer(1)
        res = self.listen_for_reply(start_time, ip)
        return res

    def listen_for_reply(self, start_time: int, ip: str) -> int:
        try:
            response, addr = self.socket.recvfrom(1024)
        except TimeoutError:
            print("reply timed out, please try again")
            sys.exit(1)
        res = self.process_data(response, start_time, ip)
        return res

    def doTraceroute(self, ip: str, port: int):
        for ttl in range(1, 65):
            while True:
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                res = self.doPing(ip=ip, port=port)
                if res:
                    continue
                break


    def start_traceroute(self):
        while True:
            try:
                addr = input("address to ping(ip:port):")
                ip, port = addr.split(":")
                port = int(port)
                if self.is_valid_ip(ip) and (0 <= port <= 65535): #is it a valid ip and port
                    self.doTraceroute(ip=ip, port=port)
                    break

                elif not self.is_valid_ip(ip): #is it an invalid ip
                    print("not a valid ip address")

                elif not (0 <= port <= 65535): #is it a inavlid port number
                    print("not a valid port number")

            except ValueError:
                print("Not in correct format")


if __name__ == "__main__":
    traceroute = Tracetoute(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))
    traceroute.start_traceroute()