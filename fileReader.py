class FileReader:
    def __init__(self):
        self.ethertypeList = []
        self.saptypeList = []
        self.ipv4typeList = []
        self.tcpPortList = []
        self.udpPortList = []
        self.icmpTypeList = []
        self.readProtocolFile()

    def readProtocolFile(self):
        file = open("protocolsCodes.txt", "r")
        mode = 0

        for lines in file:
            if lines[:-1] == '#Ethertypes':
                mode = 1
                continue

            if lines[:-1] == "#Saps":
                mode = 2
                continue

            if lines[:-1] == "#IPv4":
                mode = 3
                continue

            if lines[:-1] == "#TCP":
                mode = 4
                continue

            if lines[:-1] == "#UDP":
                mode = 5
                continue

            if lines[:-1] == "#ICMP":
                mode = 6
                continue

            if mode == 1:
                a = [lines[:4], lines[5:-1]]
                self.ethertypeList.append(a)
                continue

            if mode == 2:
                a = [lines[:2], lines[3:-1]]
                self.saptypeList.append(a)
                continue

            if mode == 3:
                a = [lines[:2], lines[3:-1]]
                self.ipv4typeList.append(a)
                continue

            if mode == 4:
                a = [lines[:4], lines[5:-1]]
                self.tcpPortList.append(a)
                continue

            if mode == 5:
                a = [lines[:4], lines[5:-1]]
                self.udpPortList.append(a)
                continue

            if mode == 6:
                a = [lines[:2], lines[3:-1]]
                self.icmpTypeList.append(a)
                continue