'''
Author: Hussain Ademola Ibrahim
e-mail: demola.hussainin@gmail.com
Phone No. : +2348039539268
Created: 24th May, 2017. 2:13 A.M
This is a python module that implements a packet sniffer. It sniffs TCP and UDP. It also sniffs IPV4 and
IPV6.It uses the struct modle to unpack each segment of the layers. AF_PAcket of the socket
object is used to imply that it uses raw socket. Note from windows 7 64bit upward, raw
socket programming is not allowed thus this module was writen n works on the Linux OS.
'socket.inet_ntoa' was used to convert binary data to src n dst IP address.
/************************************************************************/
python works with binary data dt is an array of characters (string)
or interger. Thus we cant use 'char' struct type cos we wunt b able to move
the bits around. Notie dt d smallest struct type we have is 1 byte n dis
is a string. since HDl n VSR r 4 bits each. we cant use char. Thus we use
H which is d smallest int we have. since IP fields cn never be signed
we use H.see strut module for more clarity in the python docs V.2.7.
'''
import sys
import socket
import os
import struct
# converts binary data to ASCII data n fort (hex) for MAC addresses
import binascii


def etherHeader(packet):
    IpHeader = struct.unpack("!6s6sH", packet[0:14])  # ipv4==0x0800
    # source MAC address. converts binary data into ascii dt looks like hex. MAC address is always in hex format.
    dstMac = binascii.hexlify(IpHeader[0])
    srcMac = binascii.hexlify(IpHeader[1])  # Destination MAC address
    protoType = IpHeader[2]  # next protocol (ip/ipv4,arp,icmp,ipv6)
    # hex() returns a string. it a built in finction
    nextProto = hex(protoType)

    print " "
    print "*******************ETHERNET HEADER***********************"
    print "\tDestination MAC: "+dstMac[0:2]+":"+dstMac[0:2]+":"+dstMac[2:4] + \
        ":"+dstMac[4:6]+":"+dstMac[6:8]+":"+dstMac[8:10]+":"+dstMac[10:]
    print "\tsource MAC: "+srcMac[0:2]+":"+srcMac[0:2]+":"+srcMac[2:4] + \
        ":"+srcMac[4:6]+":"+srcMac[6:8]+":"+srcMac[8:10]+":"+srcMac[10:]

    print "\tNext Protocol: "+nextProto
    # print type(nextProto). Turns out nextProto is a string bcos of the hex() which returns a srting

    # IP/IPV4 frame ethertype. check if_ether.h for other ether protocol hex values.
    if (nextProto == '0x800'):
        proto = 'IPV4'
    if (nextProto == '0x806'):  # ARP  frame. check wikipedia (ether type)
        proto = 'ARP'
    if (nextProto == '0x86dd'):  # IP/IPV6 frame. check if_ethr.h header file
        proto = 'IPV6'

    packet = packet[14:]
    return packet, proto

# Strips d next layer which is the netwrk protocol layer. Here its IPV4. Its strips each section in the IPV4 header. See IP header for more clarity.


def ipv4Header(data):
    # 6Unsigned shrt,4bytsOfStirng,4bytsOfString. 2*6byts+4byts+4byts==20byts
    packet = struct.unpack("!6H4s4s", data[0:20])
    # shift dis byte to d right by 12 bits so that only version field remains and all bits to its left is zero.
    version = packet[0] >> 12
    # Removes typ of srvc via logic shift to the right and removes version field via '&'.
    headerLenght = (packet[0] >> 8) & 0x000F
    typeOfService = packet[0] & 0x00FF  # Removes vrs n headrlen via '&'
    totalLenght = packet[1]
    identification = packet[2]
    flags = (packet[3] >> 13)
    fragOffSet = packet[3] & 0x1FFF
    ttl = packet[4] >> 8
    protocol = packet[4] & 0x00FF
    hdrChkSum = packet[5]
    srcAddress = socket.inet_ntoa(packet[6])  # _ntoa==netwotk to ascii.
    dstAddress = socket.inet_ntoa(packet[7])  # _ntoa==netwotk to ascii.

    if (protocol == 6):  # check protocol number documentation
        nextProto = 'TCP'
    elif (protocol == 17):
        nextProto = 'UDP'
    elif (protocol == 2):
        nextProto = 'IGMP'
    else:
        nextProto = 'ICMP'

    print "*******************IPv4 HEADER***********************"
    print "\tVersion: "+str(version)
    print "\tHeader Lenght: "+str(headerLenght)
    print "\tType Of Service: "+str(typeOfService)
    print "\tTotal Lenght: "+str(totalLenght)
    print "\tIdentification: "+str(identification)
    print"\tFlags: "+str(flags)
    print "\tFragment Offset: "+str(fragOffSet)
    print "\tTll: "+str(ttl)
    print "\tNext Protocol: "+str(nextProto)
    print "\tHeader checksum: "+str(hdrChkSum)
    print "\tSource Address: "+srcAddress
    print "\tDestination Address: "+dstAddress

    data = data[20:]
    return data, nextProto


def nextHeader(ipv6_next_header):
    if (ipv6_next_header == 6):
        ipv6_next_header = 'TCP'
    elif (ipv6_next_header == 17):
        ipv6_next_header = 'UDP'
    elif (ipv6_next_header == 43):
        ipv6_next_header = 'Routing'
    elif (ipv6_next_header == 1):
        ipv6_next_header = 'ICMP'
    elif (ipv6_next_header == 58):
        ipv6_next_header = 'ICMPv6'
    elif (ipv6_next_header == 44):
        ipv6_next_header = 'Fragment'
    elif (ipv6_next_header == 0):
        ipv6_next_header = 'HOPOPT'
    elif (ipv6_next_header == 60):
        ipv6_next_header = 'Destination'
    elif (ipv6_next_header == 51):
        ipv6_next_header = 'Authentication'
    elif (ipv6_next_header == 50):
        ipv6_next_header = 'Encapsuling'

    return ipv6_next_header


def ipv6Header(data):
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(
        ">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16
    traffic_class = int(traffic_class) & 4095
    flow_label = int(ipv6_first_word) & 65535

    ipv6_next_header = nextHeader(ipv6_next_header)

    print "*******************IPv6 HEADER***********************"
    print "\tVersion: %s" % (version)
    print "\tTraffic class: %s" % hex(traffic_class)
    print "\tFlow label: %s" % hex(flow_label)
    print "\tPayload Length: %s" % (ipv6_payload_legth)
    print "\tNext Header: %s" % (ipv6_next_header)
    print "\tHop limit: %s" % (ipv6_hoplimit)
    print "\tSource Address: %s" % (ipv6_src_ip)
    print "\tDestination Address: %s" % (ipv6_dst_ip)

    data = data[40:]
    return data, ipv6_next_header


def fragmentHeader(data):
    packet = struct.unpack("!2B1H1I", data[0:8])
    next_header = packet[0]
    reserved = packet[1]
    frag_offset = packet[2] >> 3
    identification = packet[3]

    next_header = nextHeader(next_header)

    print "*******************FRAGMENT HEADER******************************************************************"
    print "\tNext Header: %s" % (next_header)
    print "\tReserved: %s" % (reserved)
    print "\tFragment Offset: %s" % (frag_offset)
    print "\tIdentification: %s" % (identification)

    data = data[8:]
    return data, next_header

    return packet, identification


def routingHeader(data):
    packet = struct.unpack("!4B", data[0:4])
    next_header = packet[0]
    hdr_ext_len = packet[1]
    routing_type = packet[2]
    seg_left = packet[3]

    next_header = nextHeader(next_header)

    print "*******************ROUTING HEADER***********************************************************************"
    print "\tNext Header: %s" % (next_header)
    print "\tHeader Extension Length: %s" % (hdr_ext_len)
    print "\tRouting Type: %s" % (routing_type)
    print "\tSegments Left: %s" % (seg_left)

    data = data[int(hdr_ext_len*8 + 8):]
    return data, next_header


def hopoptHeader(data):
    packet = struct.unpack("!2b", data[0:2])
    next_header = packet[0]
    hdr_ext_len = packet[1]

    next_header = nextHeader(next_header)

    print "*********HOP-BY-HOP***********************************************************************************"
    print "\tNext Header: %s" % (next_header)
    print "\tHeader Extension Length: %s" % (hdr_ext_len*8 + 8)

    data = data[int(hdr_ext_len*8 + 8):]
    return data, next_header


def destinationHeader(data):
    packet = struct.unpack("!2b", data[0:2])
    next_header = packet[0]
    hdr_ext_len = packet[1]

    next_header = nextHeader(next_header)

    print "*********DESTINATION OPTIONS HEADER********************************************************************"
    print "\tNext Header: %s" % (next_header)
    print "\tHeader Extension Length: %s" % (hdr_ext_len*8 + 8)

    data = data[int(hdr_ext_len*8 + 8):]
    return data, next_header


def authenticationHeader(data):
    packet = struct.unpack("!2b", data[0:2])
    next_header = packet[0]
    payload_len = packet[1]

    next_header = nextHeader(next_header)

    print "*********AUTHENTICATION HEADER************************************************************************"
    print "\tNext Header: %s" % (next_header)
    print "\tHeader Extension Length: %s" % (payload_len*4 + 8)

    data = data[int(payload_len*4 + 8):]
    return data, next_header


def encapsulingHeader(data):
    #packet = struct.unpack("!2b", data[0:2])
    #next_header = packet[0]
    #payload_len = packet[1]

    #next_header = nextHeader(next_header)

    print "*********Encapsuling HEADER************************************************************************"
    #print "\tNext Header: %s" % (next_header)
    #print "\tHeader Extension Length: %s" % (payload_len*4 + 8)

    #data = data[int(payload_len*4 + 8):]
    # return data, next_header
    return data, ''


def tcpHeader(newPacket):
    # 2 unsigned short,2unsigned Int,4 unsigned short. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
    packet = struct.unpack("!2H2I4H", newPacket[0:20])
    srcPort = packet[0]
    dstPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    tcpFlags = packet[4] & 0x003F  # 1111 1111 1111 1111 & 0000 0000 0011 1111
    urgFlag = tcpFlags & 0x0020  # 1111 1111 1111 1111 & 0000 0000 0010 0000
    ackFlag = tcpFlags & 0x0010  # 1111 1111 1111 1111 & 0000 0000 0001 0000
    pushFlag = tcpFlags & 0x0008  # 1111 1111 1111 1111 & 0000 0000 0000 1000
    resetFlag = tcpFlags & 0x0004  # 1111 1111 1111 1111 & 0000 0000 0000 0100
    synFlag = tcpFlags & 0x0002  # 1111 1111 1111 1111 & 0000 0000 0000 0010
    finFlag = tcpFlags & 0x0001  # 1111 1111 1111 1111 & 0000 0000 0000 0001
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]

    print "*******************TCP HEADER***********************"
    print "\tSource Port: "+str(srcPort)
    print "\tDestination Port: "+str(dstPort)
    print "\tSequence Number: "+str(sqncNum)
    print "\tAck. Number: "+str(acknNum)
    print "\tData Offset: "+str(dataOffset)
    print "\tReserved: "+str(reserved)
    print "\tTCP Flags: "+str(tcpFlags)

    if(urgFlag == 32):
        print "\tUrgent Flag: Set"
    if(ackFlag == 16):
        print "\tAck Flag: Set"
    if(pushFlag == 8):
        print "\tPush Flag: Set"
    if(resetFlag == 4):
        print "\tReset Flag: Set"
    if(synFlag == 2):
        print "\tSyn Flag: Set"
    if(finFlag == True):
        print "\tFin Flag: Set"

    print "\tWindow: "+str(window)
    print "\tChecksum: "+str(checkSum)
    print "\tUrgent Pointer: "+str(urgPntr)
    print " "

    packet = packet[20:]
    return packet


def udpHeader(newPacket):
    packet = struct.unpack("!4H", newPacket[0:8])
    srcPort = packet[0]
    dstPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]

    print "*******************UDP HEADER***********************"
    print "\tSource Port: "+str(srcPort)
    print "\tDestination Port: "+str(dstPort)
    print "\tLenght: "+str(lenght)
    print "\tChecksum: "+str(checkSum)
    print " "

    packet = packet[8:]
    return packet


def icmpv6Header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack(
        ">BBH", data[:4])

    print "*******************ICMPv6 HEADER***********************"
    print "\tICMPv6 type: %s" % (ipv6_icmp_type)
    print "\tICMPv6 code: %s" % (ipv6_icmp_code)
    print "\tICMPv6 checksum: %s" % (ipv6_icmp_chekcsum)

    data = data[4:]
    return data


def main():
    newPacket, nextProto = '', ''
    # os.system('clear')
    packet = socket.socket(
        socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
    receivedRawPacket = packet.recv(2048)
    resultingPacket, proto = etherHeader(receivedRawPacket)

    if (proto == 'IPV4'):
        newPacket, nextProto = ipv4Header(resultingPacket)
    elif (proto == 'IPV6'):
        newPacket, nextProto = ipv6Header(resultingPacket)
    elif (proto == 'ARP'):
        print "******************ARP Protocol**********************"

    if (nextProto == 'HOPOPT'):
        newPacket, nextProto = hopoptHeader(newPacket)
    if (nextProto == 'Destination'):
        newPacket, nextProto = destinationHeader(newPacket)
    if (nextProto == 'Routing'):
        newPacket, nextProto = routingHeader(newPacket)
    if (nextProto == 'Fragment'):
        newPacket, nextProto = fragmentHeader(newPacket)
    if (nextProto == 'Authentication'):
        newPacket, nextProto = authenticationHeader(newPacket)
    if (nextProto == 'Encapsuling'):
        newPacket, nextProto = encapsulingHeader(newPacket)
    if (nextProto == 'Destination'):
        newPacket, nextProto = destinationHeader(newPacket)

    if (nextProto == 'ICMPv6'):
        remainingPacket = icmpv6Header(newPacket)
    elif (nextProto == 'TCP'):
        remainingPacket = tcpHeader(newPacket)
    elif (nextProto == 'UDP'):
        remainingPacket = udpHeader(newPacket)
    elif (nextProto == 'IGMP'):
        print "*********Internet Group Management Protocol**********"
    else:
        return


while(True):
    main()
