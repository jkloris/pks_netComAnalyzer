#materska trieda standardov, nema svoje instancie - az jej deti
class Ethernet:

    def __init__(self, packet, fileReader):
        self.dstMAC = ''
        self.srcMAC = ''
        self.type = ''
        self.fileReader = fileReader
        self.protocol = None

        self.packet = packet
        self.analyze()

    #zist MAC adresy ramca
    def analyze(self):
        for i in range(6):
            self.dstMAC += decToHex(self.packet[i]) + ':'
            self.srcMAC += decToHex(self.packet[i + 6]) + ':'

        self.dstMAC = self.dstMAC[:-1]
        self.srcMAC = self.srcMAC[:-1]

    #vypis informacii o ramci
    def whoAmI(self):
        a = f'Dlzka ramca poskytnuta pcap API: {len(self.packet)} B\n'
        a += f'Dlzka ramca prenasana po mediu: {64 if (len(self.packet) + 4) < 64 else (len(self.packet) + 4)} B\n'
        a += "Neznamy protokol" if self.type == '' else self.type
        a += f'\nZdrojova MAC adresa: {self.srcMAC}\n'
        a += f'Cielova MAC adresa: {self.dstMAC}\n'
        return a

    #vypis jednotlivych bytov ramca v monospace tvare
    def printPacket(self):
        s = ''
        a = s
        counter = 0
        for b in self.packet:
            s += decToHex(b) + " "
            counter += 1
            if counter % 8 == 0:
                s += ' '
            if counter % 16 == 0:
                print(s)
                a += s + '\n'
                s = ''
        print(s)
        a+=s
        return a

#Ethernet II
class Ethernet2(Ethernet):

    def __init__(self, packet, fileReader, communicationAnalyzer, idNum):
        self.communicationAnalyzer = communicationAnalyzer
        self.dstIP = ''
        self.srcIP = ''
        self.port = None
        self.numID = idNum
        Ethernet.__init__(self, packet, fileReader)

    def analyze(self):

        # get ether type
        for key in self.fileReader.ethertypeList:
            if (decToHex(self.packet[12]) + decToHex(self.packet[13])).lower() == key[0]:
                self.type = key[1]
                break

        # pre ARP a IPv4 ziska aj IP adresy
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

    # urci vnoreny protokol IPv4 protokolu a v niektorych pripadoch zacne analyzu komunikace
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
                    self.communicationAnalyzer.icmpCounter+=1
                    return
    # podla kodu portov priradi port a zavola funkciu na usporiadanie TCP komunikacie
    def analyzeTCP(self):
        for port in self.fileReader.tcpPortList:
            if (decToHex(self.packet[34]) + decToHex(self.packet[35])).lower() == port[0] or (decToHex(self.packet[36]) + decToHex(self.packet[37])).lower() == port[0]:
                self.port = port[1]
                break
        self.communicationAnalyzer.checkForTWH(self)

    # podla kodu portov priradi port a zavola funkciu na usporiadanie TFTP komunikacie
    def analyzeUDP(self):
        for port in self.fileReader.udpPortList:
            if (decToHex(self.packet[34]) + decToHex(self.packet[35])).lower() == port[0] or (decToHex(self.packet[36]) + decToHex(self.packet[37])).lower() == port[0]:
                self.port = port[1]
                break
        if self.port == 'tftp':
            self.communicationAnalyzer.addReadReqTFTP(self)
            return
        if self.port == None:
            self.communicationAnalyzer.analyzeTFTP(self)

    # ramcom s ICMP priradi typ spravy
    def analyzeICMP(self):
        for type in self.fileReader.icmpTypeList:
            if (decToHex(self.packet[34])).lower() == type[0]:
                self.port = type[1]
                break

    def whoAmI(self):

        a = 'Ethernet II\n'
        a += f'Dlzka ramca poskytnuta pcap API: {len(self.packet)} B\n'
        a += f'Dlzka ramca prenasana po mediu: {64 if (len(self.packet) + 4) < 64 else (len(self.packet) + 4)} B\n'
        a += f'Zdrojova MAC adresa: {self.srcMAC}\n' + f'Cielova MAC adresa: {self.dstMAC}\n'
        a += "Neznamy protokol" if self.type == '' else self.type
        if self.srcIP != "\n": a += f'\nZdrojova IP adresa: {self.srcIP}\n'
        if self.dstIP != "": a +=f'Cielova IP adresa: {self.dstIP}\n'
        if self.protocol != None:
            a += f'{self.protocol}\n'
        else:
            print(a)
            return a

        if self.protocol == "UDP" or self.protocol == "TCP":
            a += f"{'Neznamy' if self.port == None else self.port}\nZdrojovy port: {int(str(('0x' + decToHex(self.packet[34]) + decToHex(self.packet[35])).lower()), 16)}\nCielovy port: {int(str(('0x' + decToHex(self.packet[36]) + decToHex(self.packet[37])).lower()), 16)}\n"
        elif self.protocol == "ICMP":
            a +=f"ICMP type: {self.port}\n"
        print(a)
        return a

# IEEE 802.3 Raw
class IEEE802_raw(Ethernet):

    def __init__(self, packet, fileReader):
        Ethernet.__init__(self, packet, fileReader)
        self.type = "IPX"

    def whoAmI(self):
        a ='IEEE 802.3 Raw'
        a+=Ethernet.whoAmI(self)
        print(a)
        return a


# IEEE 802.3 LLC + SNAP
class IEEE802_snap(Ethernet):

    def whoAmI(self):
        a = 'IEEE 802.3 SNAP'
        a+=Ethernet.whoAmI(self)
        print(a)
        return a

    def analyze(self):
        Ethernet.analyze(self)

        for key in self.fileReader.saptypeList:
            if (decToHex(self.packet[14])).lower() == key[0]:
                self.type = key[1]
                break

# IEEE 802.3 LLC
class IEEE802_llc(Ethernet):

    def whoAmI(self):
        a = 'IEEE 802.3 LLC'
        a += Ethernet.whoAmI(self)
        print(a)
        return a

    def analyze(self):
        Ethernet.analyze(self)

        for key in self.fileReader.saptypeList:
            if (decToHex(self.packet[14])).lower() == key[0]:
                self.type = key[1]
                break

# pomocna funkcia na prehodnie int tvaru do 0x?? tvaru a to do ?? tvaru
def decToHex(n1):
    x = hex(n1)[2:]
    if len(x) == 1:
        x='0'+x
    return x