'''
http://www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/
Used this for reference for packet parsing
'''

import socket
from struct import *
import datetime
import pcapy
import os
import sys
import getopt
import time

def usage():
    print 'How to run viewer:'
    print '> python viewer -i interface -c N -r filename'
    print '-i <interface>             Listen on the specified interface'
    print '-r <read>                   Read the pcap file and print packets'
    print '-c <count>                 Print count number of packets and quit'
    print '-l <logfile>                Write debug info to specified logfile'

def view(device, count, filename):
    global c
    c = 0

    if device != None and count == -1:
        usage()
        sys.exit()

    if device != None and filename != None:
        usage()
        sys.exit()

    if device != None and filename == None:
        cap = pcapy.open_live(device, 2048, 1, 0)
        print 'viewer: listening on ' + device

    if filename != None and device == None:
       cap = pcapy.open_offline(filename)
       print 'viewer: reading ' + filename

    if count == -1 and filename != None:
        while True:
            (header, packet) = cap.next()
            parse_packet(packet)

    if count != -1 and (filename != None or device != None):
        while c < count:
            (header, packet) = cap.next()
            parse_packet(packet)

def parse_packet(packet):
    global c
    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])

    #Parse IP Packets, IP Protocol number = 8
    if eth_protocol == 8:
        #Parse IP Header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:eth_length + 20]

        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF # set to 4 bits
        iph_length = ihl * 4 # multiply by 4 to get 16 bits?

        length = iph[2]
        protocol = iph[6]
        sourceIP = socket.inet_ntoa(iph[8]);
        destIP = socket.inet_ntoa(iph[9]);

        #ICMP Packets
        if protocol == 1:
            #Parse ICMP Header
            #take first 8 characters for icmp header
            offset = iph_length + eth_length
            icmp_header = packet[offset:offset+8]

            icmph = unpack('bbHHh' , icmp_header)

            icmp_type = icmph[0]
            icmp_id = icmph[3]
            icmp_seq = icmph[4]
            if icmp_type == 0:
                icmp_type = 'reply'
                c += 1
            elif icmp_type == 8:
                icmp_type = 'request'
                c += 1

            if icmp_type == 'reply' or icmp_type == 'request':
                print str(float(time.time())) + ' ' + sourceIP + ' > ' + destIP + ': ICMP echo ' + icmp_type + ', id ' + str(icmp_id) + ', seq ' + str(icmp_seq) + ', length ' + str(length)

def main():
    if len(sys.argv) == 1:
        usage()
        sys.exit(2)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'i:c:r:l:', [])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    device = None
    count = -1
    pcap_file = None

    for opt, arg in opts:
        if opt in ('-i', '--int'):
            device = arg
        elif opt in ('-c', '--count'):
            count = int(arg)
        elif opt in ('-r', '--read'):
            pcap_file = arg
        elif opt in ('-l', '--logfile'):
            logfile = arg
        else:
            usage()
            sys.exit(2)

    view(device, count, pcap_file)

if __name__ == '__main__':
    main()
