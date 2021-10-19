class Ethernet:

    def __init__(self, packet, fileReader):
        self.dstMAC = ''
        self.srcMAC = ''
        self.type = ''
        self.fileReader = fileReader
        self.protocol = None
        # self.lenApi = None
        # self.lenMed = None

        self.packet = packet
        self.analyze()

    def analyze(self):
        for i in range(6):
            self.dstMAC += decToHex(self.packet[i]) + ':'
            self.srcMAC += decToHex(self.packet[i + 6]) + ':'

        self.dstMAC = self.dstMAC[:-1]
        self.srcMAC = self.srcMAC[:-1]

    def whoAmI(self):
        print(f'Dlzka ramca poskytnuta pcap API: {len(self.packet)} B')
        print(f'Dlzka ramca prenasana po mediu: {64 if (len(self.packet) + 4) < 64 else (len(self.packet) + 4)} B')
        print("Neznamy protokol" if self.type == '' else self.type)
        print(f'Zdrojova MAC adresa: {self.srcMAC}')
        print(f'Cielova MAC adresa: {self.dstMAC}')

    def printPacket(self):
        s = ''
        counter = 0
        for b in self.packet:
            s += decToHex(b) + " "
            counter += 1
            if counter % 8 == 0:
                s += ' '
            if counter % 16 == 0:
                print(s)
                s = ''
        print(s)


class Ethernet2(Ethernet):

    def __init__(self, packet, fileReader, communicationAnalyzer, idNum):
        self.communicationAnalyzer = communicationAnalyzer
        self.dstIP = ''
        self.srcIP = ''
        # self.protocol = None
        self.port = None
        # tmp
        self.numID = idNum
        Ethernet.__init__(self, packet, fileReader)

    def analyze(self):

        # get ether type
        for key in self.fileReader.ethertypeList:
            if (decToHex(self.packet[12]) + decToHex(self.packet[13])).lower() == key[0]:
                self.type = key[1]
                break

        for i in range(6):
            self.dstMAC += decToHex(self.packet[i]) + ':'
            self.srcMAC += decToHex(self.packet[i + 6]) + ':'
            if self.type == "IPv4" and i < 4:
                self.srcIP += str(self.packet[i + 26]) + '.'
                self.dstIP += str(self.packet[i + 30]) + '.'
            elif self.type == "ARP" and i < 4:
                self.srcIP += str(self.packet[i + 28]) + '.'
                self.dstIP += str(self.packet[i + 38]) + '.'
        self.dstMAC = self.dstMAC[:-1]
        self.srcMAC = self.srcMAC[:-1]
        self.srcIP = self.srcIP[:-1]
        self.dstIP = self.dstIP[:-1]


        if self.type == "IPv4":
            self.analyzeIPv4()
            return
        elif self.type == "ARP":
            self.communicationAnalyzer.analyzeARP(self)
            return

    def analyzeIPv4(self):
        for key in self.fileReader.ipv4typeList:
            if decToHex(self.packet[23]).lower() == key[0]:
                self.protocol = key[1]
                if key[1] == "TCP":
                    self.analyzeTCP()
                    return
                if key[1] == "UDP":
                    self.analyzeUDP()
                    return
                if key[1] == "ICMP":
                    self.analyzeICMP()
                    return

    def analyzeTCP(self):
        for port in self.fileReader.tcpPortList:
            if (decToHex(self.packet[34]) + decToHex(self.packet[35])).lower() == port[0] or (decToHex(self.packet[36]) + decToHex(self.packet[37])).lower() == \
                    port[0]:
                self.port = port[1]
                break
        self.communicationAnalyzer.checkForTWH(self)

    def analyzeUDP(self):
        for port in self.fileReader.udpPortList:
            if (decToHex(self.packet[34]) + decToHex(self.packet[35])).lower() == port[0] or (decToHex(self.packet[36]) + decToHex(self.packet[37])).lower() == \
                    port[0]:
                self.port = port[1]
                break
        if self.port == 'tftp':
            self.communicationAnalyzer.addReadReqTFTP(self)
            return
        if self.port == None:
            self.communicationAnalyzer.analyzeTFTP(self)

    def analyzeICMP(self):
        for type in self.fileReader.icmpTypeList:
            if (decToHex(self.packet[34])).lower() == type[0]:
                self.port = type[1]
                break

    def whoAmI(self):
        print('Ethernet II')
        print(f'Dlzka ramca poskytnuta pcap API: {len(self.packet)} B')
        print(f'Dlzka ramca prenasana po mediu: {64 if (len(self.packet) + 4) < 64 else (len(self.packet) + 4)} B')
        print(f'Zdrojova MAC adresa: {self.srcMAC}')
        print(f'Cielova MAC adresa: {self.dstMAC}')
        print("Neznamy protokol" if self.type == '' else self.type)
        if self.srcIP != "": print(f'Zdrojova IP adresa: {self.srcIP}')
        if self.dstIP != "": print(f'Cielova IP adresa: {self.dstIP}')
        if self.protocol != None:
            print(f'{self.protocol}')
        else:
            return

        if self.protocol == "UDP" or self.protocol == "TCP":
            print( f"{'Neznamy' if self.port == None else self.port}\nZdrojovy port: {int(str(('0x' + decToHex(self.packet[34]) + decToHex(self.packet[35])).lower()), 16)}\nCielovy port: {int(str(('0x' + decToHex(self.packet[36]) + decToHex(self.packet[37])).lower()), 16)}")
        elif self.protocol == "ICMP":
            print(f"ICMP type: {self.port}")


class IEEE802_raw(Ethernet):

    def __init__(self, packet, fileReader):
        Ethernet.__init__(self, packet, fileReader)
        self.type = "IPX"

    def whoAmI(self):
        print('IEEE 802.3 Raw')
        Ethernet.whoAmI(self)


class IEEE802_snap(Ethernet):

    def whoAmI(self):
        print('IEEE 802.3 SNAP')
        Ethernet.whoAmI(self)

    def analyze(self):
        Ethernet.analyze(self)

        for key in self.fileReader.saptypeList:
            if (decToHex(self.packet[14])).lower() == key[0]:
                self.type = key[1]
                break


class IEEE802_llc(Ethernet):

    def whoAmI(self):
        print('IEEE 802.3 LLC')
        Ethernet.whoAmI(self)

    def analyze(self):
        Ethernet.analyze(self)

        for key in self.fileReader.saptypeList:
            if (decToHex(self.packet[14])).lower() == key[0]:
                self.type = key[1]
                break


def decToHex(n1):
    x = hex(n1)[2:]
    if len(x) == 1:
        x='0'+x
    return x