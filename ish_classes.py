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
    arpComms = []

    def __init__(self, packetList):
        self.packetList = packetList


    def analyzeTFTP(self, packet):
        thisDstPort = (packet.packet[36] + packet.packet[37]).lower()
        thisSrcPort = (packet.packet[34] + packet.packet[35]).lower()
        for p in self.tftpComms:
            if len(p) == 1 and p[0].srcIP == packet.dstIP and p[0].dstIP == packet.srcIP and thisDstPort == (p[0].packet[34] + p[0].packet[35]).lower():
                packet.port = 'tftp'
                p.append(packet)
                return
            elif ((p[1].srcIP == packet.srcIP and p[1].dstIP == packet.dstIP) or (p[1].srcIP == packet.dstIP and p[1].dstIP == packet.srcIP)) and ((thisDstPort == (p[1].packet[34] + p[1].packet[35]).lower() and thisSrcPort == (p[1].packet[36] + p[1].packet[37]).lower()) or (thisSrcPort == (p[1].packet[34] + p[1].packet[35]).lower() and thisDstPort == (p[1].packet[36] + p[1].packet[37]).lower())):
                packet.port = 'tftp'
                p.append(packet)
                return


    #vytvaram 2D pole, kde prvy element je vzdy read request a posledny je flag o ukonceni komunikacie
    def addReadReqTFTP(self, packet):
        self.tftpComms.append([packet])

    def printTFTPCommunication(self):

        opcode = {
            '01': 'Read Request',
            '02': 'Write Request',
            '03': 'Data',
            '04': 'ACK',
            '05': 'ERROR',
            '06': 'OACK'
        }

        for i in self.tftpComms:
            print(f"######### TFTP komunikacia c.{self.tftpComms.index(i) + 1} #######")
            for o in range(len(i)):
                print(f"Frame #{i[o].numID}")
                i[o].whoAmI()
                print(f"[{opcode[i[o].packet[43]]}]{'; Block: ' + str(int(i[o].packet[44] + i[o].packet[45],16)) if (i[o].packet[43] == '04' or i[o].packet[43] == '03') else ''}\n_____________________________")


    def analyzeARP(self, packet):
        com = {
            'request' : [],
            'reply' : []
        }

        for i in self.arpComms:
            if packet.packet[21] == '01' and ((i['request'] != [] and i['request'][0].srcIP == packet.srcIP and  i['request'][0].dstIP == packet.dstIP ) or (i['reply'] != [] and i['reply'][0].srcIP == packet.dstIP and  i['reply'][0].srcIP == packet.dstIP)) : #mozno pridat aj kontrolu MAC
                print(packet.numID)
                i['request'].append(packet)
                return
            elif packet.packet[21] == '02' and ((i['request'] != [] and i['request'][0].srcIP == packet.dstIP and i['request'][0].dstIP == packet.srcIP) or (i['reply'] != [] and i['reply'][0].srcIP == packet.srcIP and i['reply'][0].dstIP == packet.dstIP)):
                i['reply'].append(packet)
                return
        if packet.packet[21] == '01':
            com['request'].append(packet)
            self.arpComms.append(com)
            return
        elif packet.packet[21] == '02':
            com['reply'].append(packet)
            self.arpComms.append(com)
            return

    def printARPCommunication(self):
        print(self.arpComms)
        for p in self.arpComms:
            print(f"\n######## ARP Komunikacia c.{self.arpComms.index(p)+1} ########\n")
            print(f"ARP-requests:")
            for req in p['request']:
                print(f"_________________\nFrame #{req.numID}")
                print(p['request'])
                print(req)
                # req.whoAmI()
                # req.printPacket()
            print(f"\nARP-replies:")
            for rep in p['reply']:
                print(f"_________________\nFrame #{rep.numID}")
                rep.whoAmI()
                rep.printPacket()

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

        if (int((packet.packet[47]).lower(), 16) & int("10", 16)) == 16 or (int((packet.packet[47]).lower(), 16) & int("01", 16)) == 1 or (int((packet.packet[47]).lower(), 16) & int("04", 16)) == 4 :
            for i in self.tcpComms:
                if i.synAck is not None and (self.cmpIPandPort(i.synAck, packet) or self.cmpIPandPort(i.syn, packet)) and i.success and i.automat.status != 6:
                    i.automat.updateAutomat(packet)
                    i.comm.append(packet)
                    return



    def cmpIPandPort(self, p1, p2):
        if p1.srcIP == p2.dstIP and p1.dstIP == p2.srcIP and (p1.packet[34] + p1.packet[35]).lower() == (p2.packet[36] + p2.packet[37]).lower() and (p2.packet[34] + p2.packet[35]).lower() == (p1.packet[36] + p1.packet[37]).lower():
            return True
        return False


    def printTCPCommunication(self, protSwitch):
        full = False
        part = False
        for i in self.tcpComms:
            if i.success and i.syn.port == protSwitch:
                if not full and (i.automat.status == 6 or i.automat.status == 6.1):
                    full = True
                    print(f"###### Komunikaca c.{self.tcpComms.index(i) + 1} (Uplna) #####\nFrame {i.syn.numID} [SYN]")
                    i.syn.whoAmI()
                    print(f"_____________\nFrame {i.synAck.numID} [SYN, ACK]")
                    i.synAck.whoAmI()
                    print(f"_____________\nFrame {i.ack.numID} [ACK]")
                    i.ack.whoAmI()
                    print(f"_____________\n")


                    for k in i.comm:
                        if i.comm.index(k) > 6 and i.comm.index(k) < len(i.comm) - 10: continue

                        print(f"Frame {k.numID} [{i.flagSwitch(k.packet[47].lower())}]")
                        k.whoAmI()
                         # k.printPacket()
                        print("_____________________________")

                elif not part and not (i.automat.status == 6 or i.automat.status == 6.1):
                    part = True
                    print(f"###### Komunikaca c.{self.tcpComms.index(i) + 1} (Neuplna) #####\nFrame {i.syn.numID} [SYN]")
                    i.syn.whoAmI()
                    print(f"_____________\nFrame {i.synAck.numID} [SYN, ACK]")
                    i.synAck.whoAmI()
                    print(f"_____________\nFrame {i.ack.numID} [ACK]")
                    i.ack.whoAmI()
                    print(f"_____________\n")

                    for k in i.comm:
                        if i.comm.index(k) > 6 and i.comm.index(k) < len(i.comm) - 10: continue
                        print(f"Frame {k.numID} [{i.flagSwitch(k.packet[47].lower())}]")
                        k.whoAmI()
                        # k.printPacket()
                        print("_____________________________")

                if full and part: return

class ThreeWayHandshake:

    def __init__(self,synPacket):
        self.synAck = None
        self.ack = None
        self.success = False
        self.syn = synPacket
        self.comm = []
        self.automat = FinTCPAutomat()

    def flagSwitch(self, flag):
        return {
            '01': 'FIN',
            '04': 'RST',
            '10': 'ACK',
            '11': 'FIN, ACK',
            '14': 'RST, ACK',
            '18': 'PSH, ACK',
            '19': 'FIN,PSH,ACK'
        }[flag]

class FinTCPAutomat:

    def __init__(self):
        self.status = 0

    def updateAutomat(self, packet):
        if self.status == 0 and (int((packet.packet[47]).lower(), 16) & int("11", 16))  == 17 : #FIN, ACK
            self.status = 1
            return
        if self.status == 0 and (int((packet.packet[47]).lower(), 16) & int("01", 16)) == 1: #FIN
            self.status = 2
            return
        if self.status == 0 and (int((packet.packet[47]).lower(), 16) & int("14", 16)) == 20: #RST,ACK
            self.status = 6
            return
        if self.status == 0 and (int((packet.packet[47]).lower(), 16) & int("04", 16)) == 4: #RST
            self.status = 6.1
            return


        if self.status == 1 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'):#FIN,ACK -> ACK
            self.status = 1.1
            return
        if self.status == 1.1 and (int((packet.packet[47]).lower(), 16) & int("11", 16)) == 17: #FIN,ACK -> ACK -> FIN,ACK
            self.status = 1.2
            return
        if self.status == 1.2 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'): #FIN,ACK -> ACK -> FIN,ACK -> ACK
            self.status = 6 #DONE
            return

        if self.status == 1 and (int((packet.packet[47]).lower(), 16) & int("11", 16)) == 17:#FIN,ACK -> FIN,ACK
            self.status = 1.11
            return
        if self.status == 1.11 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'): #FIN,ACK -> FIN,ACK -> ACK
            self.status = 1.12
            return
        if self.status == 1.12 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'): #FIN,ACK -> FIN,ACK -> ACK -> ACK
            self.status = 6 #DONE
            return

        if self.status == 2 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'): #FIN -> ACK
            self.status = 2.1
            return
        if self.status == 2.1 and (int((packet.packet[47]).lower(), 16) & int("01", 16)) == 1: #FIN -> ACK -> FIN
            self.status = 2.2
            return
        if self.status == 2.2 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'): #FIN -> ACK -> FIN -> ACK
            self.status = 6 #DONE
            return

        if self.status == 2 and (int((packet.packet[47]).lower(), 16) & int("04", 16)) == 4: #FIN -> RST
            self.status = 6.1
            return

        if self.status == 6.1 and (packet.packet[47].lower() == '10' or packet.packet[47].lower() == '18'): #..RST -> ACK?
            self.status = 6
            return