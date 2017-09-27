import socket
from struct import unpack
import os
import pcapy
import sys


def payload_parser(payload, data_file, idx):
    eth_length = 14
    eth_protocol = socket.ntohs(unpack('!6s6sH', payload[:eth_length])[2])

    if not eth_protocol == 8:
        return idx

    ip_header = unpack('!BBHHHBBH4s4s', payload[eth_length:20+eth_length])
    version_ih = ip_header[0]
    ip_header_length = (version_ih & 0xF) * 4
    protocol = ip_header[6]
    source_address = socket.inet_ntoa(ip_header[8])
    dest_address = socket.inet_ntoa(ip_header[9])

    if not protocol == 6:
        return idx

    tcp_header_index = ip_header_length + eth_length
    tcp_header = unpack('!HHLLBBHHH',
                        payload[tcp_header_index:tcp_header_index+20])

    source_port = tcp_header[0]
    dest_port = tcp_header[1]
    data_offset_reserved = tcp_header[4]
    tcp_header_length = data_offset_reserved >> 4

    tcp_header_size = eth_length + ip_header_length + tcp_header_length * 4
    data_list = payload[tcp_header_size:].partition(b'\r\n\r\n')[0]

    try:
        data_splited = str(data_list, 'utf-8').split('\r\n')

        if "HTTP/1.1" not in data_splited[0]:
            return idx

        data_file.write("#" + str(idx) + " " + str(source_address) + ":" +
                        str(source_port) + " " + str(dest_address) + ":" +
                        str(dest_port) + "\n")
        idx = idx + 1

        for string in data_splited:
            data_file.write(string + "\n")

        data_file.write("\n")
        return idx

    except UnicodeDecodeError:
        return idx


def main(argv):
    print("Choose right device number")
    devices = os.listdir('/sys/class/net/')

    for index, device in enumerate(devices):
        print(str(index+1) + " " + str(device))
    try:
        captured = pcapy.open_live(devices[int(input())-1], 65536, 1, 1)
    except pcapy.PcapError:
        print("Permission Denied" +
              "You don't have permission to capture on that device " +
              "(socket: Operation not permitted)")
        return 1
    (header, packet) = captured.next()
    data_file = open("./result.txt", "w")

    try:
        idx = 0
        while header is not None:
            (header, packet) = captured.next()
            idx = payload_parser(packet, data_file, idx)

    except KeyboardInterrupt:
        data_file.close()
        return 0


if __name__ == "__main__":
    main(sys.argv)
