class IpCounter:
    allIPs = {}

    def addIP(self, ip):
        if self.allIPs.get(ip) != None:
            self.allIPs[ip]+=1
            return
        self.allIPs[ip] = 1



    def printAllIPs(self):
        for i in self.allIPs.keys():
            print(i)

    #TODO osetrit ak ich je viac
    def getMostFrequentIP(self):
        return max(self.allIPs, key=self.allIPs.get)

class CommunicationAnalyzer:

    tftpComms = []
    tcpComms = []
    def __init__(self, packetList):
        self.packetList = packetList

    #TODO trace-15 packet 49 je problem, lebo nesedia porty a potom neukazuje, že to je tftp
    def analyzeTFTP(self, packet):
            i = len(self.tftpComms) - 1

            if self.tftpComms[i][-1] == 1:
                return

            preSrcPort = (self.tftpComms[i][-2].packet[34] + self.tftpComms[i][-2].packet[35]).lower()
            thisDstPort = (packet.packet[36] + packet.packet[37]).lower()
            if preSrcPort == thisDstPort:
                packet.port = 'tftp'
                self.tftpComms[i].insert(-1, packet)
                #TODO osetri krajne pripady
                # if packet.packet[43] == '03' and len(packet.packet) < 558:


    #vytvaram 2D pole, kde prvy element je vzdy read request a posledny je flag o ukonceni komunikacie
    def addReadReqTFTP(self, packet):
        if len(self.tftpComms) > 0:
            self.tftpComms[-1][-1] = 1
        self.tftpComms.append([packet, 0])

    def printTFTPCommunication(self):
        for i in self.tftpComms:
            print(f"############# TFTP komunikacia cislo {self.tftpComms.index(i) + 1}")
            for o in range(len(i)-1):
                i[o].whoAmI()
                print(f"({i[o].packet[43]} {'Block ' +i[o].packet[44]+ i[o].packet[45] if (i[o].packet[43] != '01' and i[o].packet[43] != '05') else ('Read Request' if i[o].packet[43] == '01' else 'Error' )})\n_____________________________")


    #tcp communicatoin
    def checkForTWH(self, packet):
        if packet.packet[47].lower() == '02':
            self.tcpComms.append(ThreeWayHandshake(packet))
            return

        if packet.packet[47].lower() == '12':
            for i in self.tcpComms:
                if self.cmpIPandPort(i.syn, packet) and i.synAck is None and i.ack is None and not i.success:
                    i.synAck = packet
                    return

        if packet.packet[47].lower() == '10':
            for i in self.tcpComms:
                if i.synAck is not None and self.cmpIPandPort(i.synAck, packet) and i.ack is None and not i.success:
                    i.ack = packet
                    i.success = True
                    return
                elif i.synAck is not None and (self.cmpIPandPort(i.synAck, packet) or self.cmpIPandPort(i.syn, packet)) and i.success:
                    i.comm.append(packet)
                    return




    def cmpIPandPort(self, p1, p2):
        if p1.srcIP == p2.dstIP and p1.dstIP == p2.srcIP and (p1.packet[34] + p1.packet[35]).lower() == (p2.packet[36] + p2.packet[37]).lower() and (p2.packet[34] + p2.packet[35]).lower() == (p1.packet[36] + p1.packet[37]).lower():
            return True
        return False


    def printTCPCommunication(self):
        for i in self.tcpComms:
            if self.tcpComms.index(i) > 3: return
            print(f"######Comm num{self.tcpComms.index(i)}\nSyn:")
            i.syn.whoAmI()
            print("_____________\nSyn + Ack:")
            i.synAck.whoAmI()
            print("_____________\nAck:")
            i.ack.whoAmI()
            print("_____________\nzvysok komunikacie:")


            for k in i.comm:
                print(k.numID)
                k.whoAmI()
                # k.printPacket()
                print("_____________________________")


class ThreeWayHandshake:
    synAck = None
    ack = None
    success = False

    def __init__(self,synPacket):
        self.syn = synPacket
        self.comm = []