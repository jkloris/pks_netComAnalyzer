from scapy.utils import rdpcap
import sys
# from scapy.all import *
from ish_classes import *
from frames import *
from fileReader import *
pcapFile = './pcaps/trace-26.pcap'
pcaps = rdpcap(pcapFile)

# print(pcaps.hexdump())

def pcapToBList(pcap):
    packetList = []

    for i in pcap:
        x = bytes(i).hex()

        s = ''
        packet = []
        for o in range(0, len(x) , 2):
            s += x[o:o + 2] + ' '
            packet.append(x[o:o + 2])
        # print(s)
        packetList.append(packet)

    return packetList

def analyzePacket(packet, fileReader):
    x = packet[12]+packet[13]
    frame = None

    if x >= '0800':
        frame = Ethernet2(packet, fileReader)

        if "IPv4" in frame.type:
            ipCounter.addIP(frame.srcIP)
    else:
        if (packet[14]+packet[15]).lower() == 'aaaa' :
            frame = IEEE802_snap(packet, fileReader)
        elif (packet[14]+packet[15]).lower() == 'ffff' :
            frame = IEEE802_raw(packet, fileReader)
        else:
            frame = IEEE802_llc(packet, fileReader)
    return frame

def printAllPacketInfo(analyzedPackets):
    for p in analyzedPackets:
        if p != None:
            print(f'Frame #{analyzedPackets.index(p) + 1}')
            p.whoAmI()
            p.printPacket()
            print("____________________________________________________")

            # if analyzedPackets.index(p) > 20:
            #     break
    ipCounter.printAllIPs()
    print(f"Najviac paketov ({ipCounter.allIPs[ipCounter.getMostFrequentIP()]}) odoslal {ipCounter.getMostFrequentIP()}")

packetList = pcapToBList(pcaps)
fileReader = FileReader()
ipCounter = IpCounter()


analyzedPack = []
for p in packetList:
    analyzedPack.append(analyzePacket(p, fileReader))
x = None
while x!= 'k':
    x = input()
    if x == '1':
        printAllPacketInfo(analyzedPack)
        continue