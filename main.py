from scapy.utils import rdpcap
from ish_classes import *
from frames import *
from fileReader import *
import os


def pcapToBList(pcap):
    packetList = []

    for i in pcap:
        packetList.append(list(bytes(i)))
        # x = bytes(i).hex()
        #
        # s = ''
        # packet = []
        # for o in range(0, len(x) , 2):
        #     s += x[o:o + 2] + ' '
        #     packet.append(x[o:o + 2])
        # # print(s)
        # packetList.append(packet)
    return packetList



def analyzePacket(packet, fileReader, ipCounter, communicationAnalyzer, idNum):
    x = decToHex(packet[12])+decToHex(packet[13])

    frame = None

    if x >= '0800':
        frame = Ethernet2(packet, fileReader, communicationAnalyzer, idNum)

        if "IPv4" in frame.type:
            ipCounter.addIP(frame.srcIP)
    else:
        y = (decToHex(packet[14])+decToHex(packet[15])).lower()
        if y == 'aaaa' :
            frame = IEEE802_snap(packet, fileReader)
        elif y == 'ffff' :
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
    numID = 1
    for p in packetList:
        analyzedPack.append(analyzePacket(p, fileReader,ipCounter, communicationAnalyzer, numID))
        numID+=1
    return analyzedPack


def printICMPcomms(analyzedPack, number):
    counter = 0
    for i in analyzedPack:
        if i.protocol == 'ICMP':
            counter+=1
            if counter > 10 and counter <= number - 10:
                continue
            print(f"_________________\nFrame #{i.numID}")
            i.whoAmI()
            i.printPacket()


def main():

    pcaps = rdpcap(getChosenPcapFile())

    packetList = pcapToBList(pcaps)
    fileReader = FileReader()
    ipCounter = IpCounter()
    communicationAnalyzer = CommunicationAnalyzer(packetList)
    analyzedPack = getAnalyzedPackets(packetList, fileReader,ipCounter, communicationAnalyzer)


    # printAllPacketInfo(analyzedPack, ipCounter)
    x = None
    # communicationAnalyzer.printTCPCommunication("https (ssl)", 6)
    while x != 11:
        print("Zvol moznosť:")
        print("1....Vypis vsetkych ramcov (bod 1.-3.)")
        print("2....Vypis ICMP komunikacie")
        print("3....Vypis ARP komunikacie")
        print("4....Vypis TFTP komunikacie")
        print("5....Vypis HTTP komunikacie")
        print("6....Vypis HTTPS komunikacie")
        print("7....Vypis SSH komunikacie")
        print("8....Vypis TELNET komunikacie")
        print("9....Vypis FTP riadiacej komunikacie")
        print("10...Vypis FTP datovej komunikacie")
        print("11...Koniec programu")
        x = int(input())

        if x == 1:
            printAllPacketInfo(analyzedPack, ipCounter)
            continue
        if x == 2:
            printICMPcomms(analyzedPack, communicationAnalyzer.icmpCounter)
            continue
        if x == 3:
            communicationAnalyzer.printARPCommunication()
            continue
        if x == 4:
            communicationAnalyzer.printTFTPCommunication()
            continue
        if x == 5:
            communicationAnalyzer.printTCPCommunication("http")
            continue
        if x == 6:
            communicationAnalyzer.printTCPCommunication("https (ssl)")
            continue
        if x == 7:
            communicationAnalyzer.printTCPCommunication("ssh")
            continue
        if x == 8:
            communicationAnalyzer.printTCPCommunication("telnet")
            continue
        if x == 9:
            communicationAnalyzer.printTCPCommunication("ftp-control")
            continue
        if x == 10:
            communicationAnalyzer.printTCPCommunication("ftp-data")
            continue









if __name__== "__main__":
    main()

#TODO:
#   ~pri 3wh ukazuje http aj ked tam nie je (asi nechat tak)
#       -spytat sa na FIN a spravit to
#       -edge case, ked na skoncenom porte zacne novy handshake
#   ~TFTP: trace-15 packet 49 je problem, lebo nesedia porty a potom neukazuje, že to je tftp
#       ~osetri krajne pripady (if packet.packet[43] == '03' and len(packet.packet) < 558:)
#       -upravit vypis
#   ~viac najcastejsich adries
#   ~ARP komunikacia