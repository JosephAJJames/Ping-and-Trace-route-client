from ping import Ping
import socket
import struct
import os
from time import perf_counter

class Tracetoute(Ping):
    def __init__(self, sock):
        super().__init__(sock)

    def doTraceroute(self, ip: str, port: int):
        for ttl in range(1, 65):
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            self.doPing(ip=ip, port=port)

    def start_traceroute(self):
        while True:
            try:
                addr = input("address to ping(ip:port):")
                ip, port = addr.split(":")
                port = int(port)
                if self.is_valid_ip(ip) and (0 <= port <= 65535): #is it a valid ip and port
                    print("doing traceroute")
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