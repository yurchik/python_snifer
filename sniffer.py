import socket
import struct
import textwrap

TAB_1 = '\t -  '
TAB_2 = '\t\t -  '
TAB_3 = '\t\t\t -  '
TAB_4 = '\t\t\t\t -  '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print("Destination: {} Source: {} Proto: {}".format(dest_mac, src_mac, eth_proto))


# Unpakc Ethernet data
def ethernet_frame(data):
    mac_dest, mac_src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(mac_dest), get_mac_addr(mac_src), socket.htons(proto), data[:14]


# Return properly formating mac
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Return properly formatted IPv4 address
def ipv4(address):
    return '.'.join(map(str, address))


main()
