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
    def __init__(self, packetList):
        self.packetList = packetList

    #TODO trace-15 packet 49 je problem, lebo nesedia porty a potom neukazuje, že to je tftp
    def analyzeTFTP(self, packet):
            for i in range(len(self.tftpComms)):
                if self.tftpComms[i][-1] == 0:
                    break

            preSrcPort = (self.tftpComms[i][-2].packet[34] + self.tftpComms[i][-2].packet[35]).lower()
            thisDstPort = (packet.packet[36] + packet.packet[37]).lower()
            if preSrcPort == thisDstPort:
                packet.port = 'tftp'
                self.tftpComms[i].insert(-1, packet)

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
