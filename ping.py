import socket
import struct


class ping:
    def __init__(self, socket):
        self.socket = socket


    def doPing(self, address):
