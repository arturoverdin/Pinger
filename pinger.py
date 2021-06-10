import os
import select
import socket
import argparse
import struct
import time

ICMP_ECHO_REQUEST = 8
RESPONSE_TIME = []


# print_ping_stats takes care of all the printing and min, max, avg calculation
def print_ping_stats(message, count, destination):
    print("Pinging {0} with {1} bytes of data \"{2}\"".format(str(destination), str(len(message.encode('utf-8'))),
                                                              message))
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

    i = 0
    while i < count:
        id = os.getpid() & 0xFFFF
        packet = create_packet(id, message, i + 1)
        sock.sendto(packet, (destination, 1))
        print(receive_ping(sock, id, 1, destination, i))
        i += 1

    sock.close()

    # below is all the checking for min, max, and average
    min_time = 100
    max_time = -1
    average = 0
    lost = 0

    for x in RESPONSE_TIME:
        if x == -1:
            lost += 1
        else:
            if x < min_time:
                min_time = x
            if x > max_time:
                max_time = x

            average = average + x

    if min_time == -1:
        min_time = "N/A"
    if max_time == 100:
        max_time = "N/A"

    if (count - lost) == 0:
        average = "N/A"
        print("Approximate round trip times in milliseconds: Minimum = {0}, Maximum = {1}, Average = {2}".format(
            str(min_time), str(max_time), str(average)))
    else:
        average = round(average / (count - lost), 3)
        print("Approximate round trip times in milliseconds: Minimum = {0}ms, Maximum = {1}ms, Average = {2}ms".format(
            str(min_time), str(max_time), str(average)))

    print("Ping statistics for {0}: Packets: Sent = {1}, Received = {2}, Lost = {3} ({4}% loss)".format(
        destination, str(count), str(count - lost), str(lost), str(round((100 * (lost / count)), 1))))

    RESPONSE_TIME.clear()
    return str(min_time) + "," + str(max_time) + "," + str(average)


# receive_ping waits for the echo reply to come in and parses it. Calculates the time rounded to 3 decimal places.
def receive_ping(sock, id, timeout, ip, count):
    timeLeft = timeout

    while True:
        start = time.time()
        ready = select.select([sock], [], [], timeLeft)
        howLong = (time.time() - start)

        if not ready[0]:
            RESPONSE_TIME.append(-1)
            return "N/A,N/A,N/A"

        recPacket, addr = sock.recvfrom(1024)

        # separating the icmp header into readable information also did the checksum error checking.
        icmpHeader = recPacket[20:28]
        data = recPacket[28:len(recPacket)]
        corrupt = checksum(icmpHeader + data)
        type, code, check, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        # separating the ip header into readable information
        ipHeader = recPacket[:20]
        version, type, length, ip, flags, ttl, proto, ip_check, ip_src, ip_dest = struct.unpack(
            "!BBHHHBBHII", ipHeader
        )

        # below is some basic error checking, if fails then it will automatically consider it corrupted
        if packetID == id and not corrupt:
            RESPONSE_TIME.append(round(howLong * 1000, 3))
            return "Reply from " + str(addr[0]) + ": " + "bytes=" + str(len(data)) + " time=" + str(
                round(howLong * 1000, 3)) + "ms TTL=" + str(ttl)

        timeLeft = timeLeft - howLong

        if timeLeft <= 0:
            RESPONSE_TIME.append(-1)
            return "N/A,N/A,N/A"


# taken from stack overflow. I lost the link though. The TA (Ziqian) linked it to me.
def checksum(packet):
    total = 0

    # Add up 16-bit words
    num_words = len(packet) // 2
    for chunk in struct.unpack("!%sH" % num_words, packet[0:num_words * 2]):
        total += chunk

    # Add any left over byte
    if len(packet) % 2:
        total += packet[-1] << 8

    # Fold 32-bits into 16-bits
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total + 0x10000 & 0xffff


# creates the icmp header + data packet that will be sent as an echo request
def create_packet(id, message, sequence):
    # type, code, checksum, ID, sequence number, data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, sequence)

    data = message.encode('utf-8')
    check = checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(check), id, sequence)

    return header + data


if __name__ == "__main__":
    COUNT = 10  # default number of packets sent

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", required=True
                        , help="Payload.")

    parser.add_argument("-c", help="Number of packets used to compute RTT. Default = 10."
                        , type=int)

    parser.add_argument("-d", required=True
                        , help="Destination IP of the pinged message.")

    args = parser.parse_args()

    PAYLOAD = str(args.p)
    DESTINATION_IP = args.d
    if args.c:
        COUNT = args.c

    print(print_ping_stats(PAYLOAD, COUNT, DESTINATION_IP))
