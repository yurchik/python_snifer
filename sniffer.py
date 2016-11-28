import socket
import struct
import textwrap


# Unpakc Ethernet data
def ethernet_frame(data):
    mac_dest, mac_src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(mac_dest), get_mac_addr(mac_src), socket.htons(proto), data[:14]


# Return properly formating mac
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()
