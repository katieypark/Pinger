import sys
import getopt
import socket
import os
import time
import struct
import select

def instructions():
    print '-l, --logfile     Write the debug info to the specified logfile'
    print '-p, --payload     The string to include in the payload'
    print '-c, --count       The number of packets used to compute RTT'
    print '-d, --dst         The destination IP for the ping message'

def ping(logfile, count, destIP, payload):
    no_bytes = len(payload)
    print "Pinging " + destIP + " with " + str(no_bytes) + " bytes of data '" + payload + "'"
    logfile.write("Pinging " + destIP + " with " + str(no_bytes) + " bytes of data '" + payload + "'" + "\n")

    no_dropped = 0
    avg_time = 0
    max_time = 0
    min_time = sys.float_info.max
    replies_recieved = 0
    packets_dropped=0
    counter = count
    while (counter > 0):
        counter -= 1
        delay = send_ping(logfile, destIP, payload, 1)
        logfile.write("Tried to send ping to " + destIP + "\n")
        if delay == None:
            time_expended = None
            logfile.write("Dropped packet" + "\n")
        else:
            ttl = delay[0]
            time_expended = delay[1]
            logfile.write("Reply recieved ttl = " + str(ttl) + "time expended = " + str(time_expended) + "\n")
        if time_expended != None:
            time_expended *= 1000
            time_expended = int(time_expended)
            if max_time < time_expended:
                max_time = time_expended
            if min_time > time_expended:
                min_time = time_expended
            replies_recieved += 1
            avg_time += time_expended
            print " Reply from " + destIP + ": bytes=" + str(no_bytes) + " time=" + str(time_expended) + "ms TTL=" + str(ttl)
        else:
            packets_dropped += 1


    print "Ping statistics for " + destIP + ": "
    percent_lost = int((float(packets_dropped) / float(count)) * 100)
    print " Packets: Sent = " + str(count) + ", Received = " + str(replies_recieved) + ", Lost = " + str(packets_dropped) + " (" + str(percent_lost) + "% loss),"
    if percent_lost<100:
        print " Approximate round trip times in milli-seconds: "
        avg_time /= count
        print " Minimum = " + str(min_time) + "ms, Maximum = " + str(max_time) + "ms, Average = " + str(avg_time) + "ms"

def send_ping(logfile, destIP, payload, timeout):
    icmp = socket.getprotobyname("icmp")
    try:
        ping_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        logfile.write("trying to create raw socket" + "\n")
    except ping_socket.error:
        print "Failed to create socket"

    try:
        destIP = socket.gethostbyname(destIP)
    except socket.gaierror:
        pass
    #calculate checksum and create packet
    header = struct.pack('bbHHh', 8, 0, 0, os.getpid(), 1)
    new_checksum = checksum(header+payload)
    header = struct.pack('bbHHh', 8, 0, socket.htons(new_checksum), os.getpid(), 1)
    packet = header + payload

    try:
        address = (destIP, 1)
        ping_socket.sendto(packet, address)
        logfile.write("sending packet" + "\n")
    except:
        print "Network is unreachable"
        sys.exit()
    delay = return_ping(logfile, ping_socket, os.getpid(), time.time(), timeout)
    ping_socket.close()
    return delay

def return_ping(logfile, ping_socket, osID, senttime, timeout):
    time_remaining = timeout
    while True:
        currenttime = time.time()
        sockready = select.select([ping_socket], [], [], time_remaining)
        timeselect = (time.time() - currenttime)
        if not sockready[0]: # ([], [], [])
            logfile.write("timeout" + "\n")
            return

        time_received = time.time()
        returnpacket, address = ping_socket.recvfrom(1024)
        # unpack icmp message 
        icmpEchoMessage = returnpacket[20:28]
        icmp_type, icmp_code, icmp_cksum, icmp_id, icmp_seq = struct.unpack('bbHHh', icmpEchoMessage)
        # unpack the ip header
        ipHeader = returnpacket[0:20]
        ipVer, tos, total_length, identification, flags, timetolive, protocol, ipchecksum, ip_src, ip_dest = struct.unpack('bbhhhbbhii', ipHeader)
        # if return packet id is the same as the sent packet id
        if icmp_id == osID:
            logfile.write("correct packet recieved" + "\n")
            returntime = time_received - senttime
            return (timetolive, returntime)

        time_remaining -= timeselect
        if time_remaining <= 0:
            return

def checksum(source_string):
    count = 0
    total = 0
    counter = (len(source_string) / 2) * 2
    while counter>count:
        val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        count += 2
        total += val
        total = total & 0xffffffff # hack to make it 32 bits long

    if len(source_string) > counter:
        total += ord(source_string[len(source_string) - 1])
        total = total & 0xffffffff # hack to make it 32 bits long

    # straight up magic
    total = (total >> 16) + (total & 0xffff)
    total = total + (total >> 16)
    check_sum = ~total
    check_sum = check_sum & 0xffff

    # swap bytes
    check_sum = check_sum >> 8 | (check_sum << 8 & 0xff00)
    return check_sum

def main():
    if len(sys.argv) == 1:
            instructions()
            sys.exit(2)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'l:p:c:d:', [])
    except getopt.GetoptError:
        instructions()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-l'):
            file_name = arg
        elif opt in ('-p'):
            payload = arg
        elif opt in ('-c'):
            count = int(arg)
        elif opt in ('-d'):
            destIP = arg
        else:
            instructions()
            sys.exit(2)

    logfile = open(file_name, 'w')
    ping(logfile, count, destIP, payload)


if __name__ == '__main__':
    main()