import socket
import struct


class ping:
    def __init__(self, socket):
        self.socket = socket

    def checksum(self ,source_string) -> int:
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


    def pack_icmp_header(self) -> bytes:

        pass
    def doPing(self):
        pass

    def is_valid_ip(self, ip):
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
                if self.is_valid_ip(ip) and not(0 <= port <= 65535): #is it a valid ip and port
                    self.doPing()
                    break

                elif not self.is_valid_ip(ip): #is it a invalid ip
                    print("not a valid ip address")

                elif not (0 <= port <= 65535): #is it a inavlid port number
                    print("not a valid port number")

            except ValueError:
                print("Not in correct format")
        pass


ping = ping(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
ping.start()