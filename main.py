from scapy.utils import rdpcap
from ish_classes import *
from frames import *
from fileReader import *
import os


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

def analyzePacket(packet, fileReader, ipCounter, communicationAnalyzer, idNum):
    x = packet[12]+packet[13]
    frame = None

    if x >= '0800':
        frame = Ethernet2(packet, fileReader, communicationAnalyzer, idNum)

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

def printAllPacketInfo(analyzedPackets, ipCounter):
    for p in analyzedPackets:
        if p != None:
            print(f'Frame #{analyzedPackets.index(p) + 1}')
            p.whoAmI()
            p.printPacket()
            print("____________________________________________________")
        # if analyzedPackets.index(p) > 100:
        #     break

    print("Vsetky zdrojove adresy (IPv4):")
    ipCounter.printAllIPs()
    print(f"Najviac paketov ({ipCounter.allIPs[ipCounter.getMostFrequentIP()]}) odoslal {ipCounter.getMostFrequentIP()}")

def getPcapFiles():
    path = './pcaps'
    return os.listdir(path)


def getChosenPcapFile():
    for p in getPcapFiles():
       print(f'#{getPcapFiles().index(p) + 1} {p}')

    print("\n-Vyber cislo pcap suboru, ktory chces analyzovat:")
    a = int(input())
    pcapFile = './pcaps/'+getPcapFiles()[a-1]

    return  pcapFile

def getAnalyzedPackets(packetList, fileReader,ipCounter, communicationAnalyzer):
    analyzedPack = []
    for p in packetList:
        analyzedPack.append(analyzePacket(p, fileReader,ipCounter, communicationAnalyzer, packetList.index(p)))
    return analyzedPack

def main():

    # a = [1,2,3,4,6]
    # a.insert(-1,5)
    # print(a[-2])
    # input()

    pcaps = rdpcap(getChosenPcapFile())

    packetList = pcapToBList(pcaps)
    fileReader = FileReader()
    ipCounter = IpCounter()
    communicationAnalyzer = CommunicationAnalyzer(packetList)
    analyzedPack = getAnalyzedPackets(packetList, fileReader,ipCounter, communicationAnalyzer)

    # printAllPacketInfo(analyzedPack, ipCounter)

    communicationAnalyzer.printTCPCommunication()

if __name__== "__main__":
    main()