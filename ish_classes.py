# Ukladanie IP adries a pocet ich volani
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

    def getMostFrequentIP(self):
        return max(self.allIPs, key=self.allIPs.get)

# Analyzuje zlozitejsie komunikacie
class CommunicationAnalyzer:

    tftpComms = []
    tcpComms = []
    arpComms = []
    icmpCounter = 0

    def __init__(self, packetList):
        self.packetList = packetList


    def analyzeTFTP(self, packet):
        thisDstPort = (decToHex(packet.packet[36]) + decToHex(packet.packet[37])).lower()
        thisSrcPort = (decToHex(packet.packet[34]) + decToHex(packet.packet[35])).lower()

        # Prejde vsetkymi zacatymi komunikaciami a kontroluje, ci tam nahodou nepatri ramec. Ak ano, prida ho
        for p in self.tftpComms:
            if len(p) == 1 and p[0].srcIP == packet.dstIP and p[0].dstIP == packet.srcIP and thisDstPort == (decToHex(p[0].packet[34]) + decToHex(p[0].packet[35])).lower():
                packet.port = 'tftp'
                p.append(packet)
                return
            elif ((p[1].srcIP == packet.srcIP and p[1].dstIP == packet.dstIP) or (p[1].srcIP == packet.dstIP and p[1].dstIP == packet.srcIP)) and ((thisDstPort == (decToHex(p[1].packet[34]) + decToHex(p[1].packet[35])).lower() and thisSrcPort == (decToHex(p[1].packet[36]) + decToHex(p[1].packet[37])).lower()) or (thisSrcPort == (decToHex(p[1].packet[34]) + decToHex(p[1].packet[35])).lower() and thisDstPort == (decToHex(p[1].packet[36]) + decToHex(p[1].packet[37])).lower())):
                packet.port = 'tftp'
                p.append(packet)
                return


    # zaciatok TFTP komunikacie
    def addReadReqTFTP(self, packet):
        self.tftpComms.append([packet])

    # Vypis TFTP komunikace
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
                # limit na 20 ramcov
                if o >= 10 and o < len(i)-10:
                    continue
                print(f"Frame #{i[o].numID}")
                i[o].whoAmI()
                print(f"[{opcode[decToHex(i[o].packet[43])]}]{'; Block: ' + str(int(decToHex(i[o].packet[44]) + decToHex(i[o].packet[45]),16)) if (decToHex(i[o].packet[43]) == '04' or decToHex(i[o].packet[43]) == '03') else ''}")
                i[o].printPacket()
                print("_____________________________")

    #analyza ARP komunikacie
    def analyzeARP(self, packet):
        # do requestu dava vsetky requesty kym nepride reply
        # ak je closed == True, komunikacia je uzavreta
        com = {
            'request' : [],
            'reply' : [],
            'closed' : False
        }

        for i in self.arpComms:
            # podla IP adresy najde a popripade priradi ramec do komunikacie ako request alebo reply
            if decToHex(packet.packet[21]) == '01' and not i['closed'] and ((i['request'] != [] and i['request'][0].srcIP == packet.srcIP and  i['request'][0].dstIP == packet.dstIP ) or (i['reply'] != [] and i['reply'][0].srcIP == packet.dstIP and  i['reply'][0].srcIP == packet.dstIP)) : #mozno pridat aj kontrolu MAC
                i['request'].append(packet)
                return
            elif decToHex(packet.packet[21]) == '02' and not i['closed'] and ((i['request'] != [] and i['request'][0].srcIP == packet.dstIP and i['request'][0].dstIP == packet.srcIP) or (i['reply'] != [] and i['reply'][0].srcIP == packet.srcIP and i['reply'][0].dstIP == packet.dstIP)):
                i['reply'].append(packet)
                i['closed'] = True
                return
        #krajny pripad, ked na danej IP adrese este nie je komunikacia
        if decToHex(packet.packet[21]) == '01':
            com['request'].append(packet)
            self.arpComms.append(com)
            return
        elif decToHex(packet.packet[21]) == '02':
            com['reply'].append(packet)
            com['closed'] = True
            self.arpComms.append(com)
            return

    # vypis ARP Komunikacie
    def printARPCommunication(self):

        for p in self.arpComms:
            print(f"\n######## ARP Komunikacia c.{self.arpComms.index(p)+1} ########\n")
            print(f"ARP-requests:")

            if len(p['request']) > 0:
                print(f"IP adresa: {p['request'][0].dstIP}, MAC adresa: ???")
            else:
                print("--Nenasli sa--")

            count = 0
            for req in p['request']:
                #limit na 20 ramcov
                if count >= 10 and count < len(p['request'])-10:
                    continue
                count += 1

                print(f"_________________\nFrame #{req.numID}")
                req.whoAmI()
                req.printPacket()
            print(f"\nARP-replies:")
            if len(p['reply']) > 0:
                print(f"IP adresa: {p['reply'][0].srcIP}, MAC adresa: {p['reply'][0].srcMAC}")
            else: print("--Nenasli sa--")

            for rep in p['reply']:
                print(f"_________________\nFrame #{rep.numID}")
                rep.whoAmI()
                rep.printPacket()

    #tcp communicatoin
    def checkForTWH(self, packet):
        # zachytenie paketu s flagom SYN
        if decToHex(packet.packet[47]).lower() == '02':
            self.tcpComms.append(ThreeWayHandshake(packet))
            return

        # zachytenie paketu s flagom SYN, ACK
        if decToHex(packet.packet[47]).lower() == '12':
            for i in self.tcpComms:
                if self.cmpIPandPort(i.syn, packet) and i.synAck is None and i.ack is None and not i.success:
                    i.synAck = packet
                    return

        # zachytenie paketu s flagom ACK
        if decToHex(packet.packet[47]).lower() == '10':
            for i in self.tcpComms:
                if i.synAck is not None and self.cmpIPandPort(i.synAck, packet) and i.ack is None and not i.success:
                    i.ack = packet
                    i.success = True
                    return

        # zachytenie paketu s flagom ACK, FIN alebo RST
        if (packet.packet[47] & int("10", 16)) == 16 or (packet.packet[47] & int("01", 16)) == 1 or (packet.packet[47] & int("04", 16)) == 4 :
            for i in self.tcpComms:
                if i.synAck is not None and (self.cmpIPandPort(i.synAck, packet) or self.cmpIPandPort(i.syn, packet)) and i.success and i.automat.status != 6:
                    i.automat.updateAutomat(packet)
                    i.comm.append(packet)
                    return


    # porovnanie adries a portov ramcov
    def cmpIPandPort(self, p1, p2):
        if p1.srcIP == p2.dstIP and p1.dstIP == p2.srcIP and (decToHex(p1.packet[34]) + decToHex(p1.packet[35])).lower() == (decToHex(p2.packet[36]) + decToHex(p2.packet[37])).lower() and (decToHex(p2.packet[34]) + decToHex(p2.packet[35])).lower() == (decToHex(p1.packet[36]) + decToHex(p1.packet[37])).lower():
            return True
        return False

    # vypis TCP komunikacie
    def printTCPCommunication(self, protSwitch):
        full = False
        part = False

        for i in self.tcpComms:
            if i.success and i.syn.port == protSwitch:
                if not full and (i.automat.status == 6 or i.automat.status == 6.1):
                    full = True
                    print(f"###### Komunikaca c.{self.tcpComms.index(i) + 1} (Kompletna) #####\nFrame {i.syn.numID} [SYN]")
                    i.syn.whoAmI()
                    i.syn.printPacket()
                    print(f"_____________\nFrame {i.synAck.numID} [SYN, ACK]")
                    i.synAck.whoAmI()
                    i.synAck.printPacket()
                    print(f"_____________\nFrame {i.ack.numID} [ACK]")
                    i.ack.whoAmI()
                    i.ack.printPacket()
                    print(f"_____________\n")

                    # limit na 20 ramcov
                    for k in i.comm:
                        if i.comm.index(k) > 6 and i.comm.index(k) < len(i.comm) - 10: continue

                        print(f"Frame {k.numID} [{i.flagSwitch(decToHex(k.packet[47]).lower())}]")
                        k.whoAmI()
                        k.printPacket()
                        print("_____________________________")

                elif not part and not (i.automat.status == 6 or i.automat.status == 6.1):
                    part = True
                    print(f"###### Komunikaca c.{self.tcpComms.index(i) + 1} (Nekompletna) #####\nFrame {i.syn.numID} [SYN]")
                    i.syn.whoAmI()
                    print(f"_____________\nFrame {i.synAck.numID} [SYN, ACK]")
                    i.synAck.whoAmI()
                    print(f"_____________\nFrame {i.ack.numID} [ACK]")
                    i.ack.whoAmI()
                    print(f"_____________\n")

                    for k in i.comm:
                        if i.comm.index(k) > 6 and i.comm.index(k) < len(i.comm) - 10: continue
                        print(f"Frame {k.numID} [{i.flagSwitch(decToHex(k.packet[47]).lower())}]")
                        k.whoAmI()
                        # k.printPacket()
                        print("_____________________________")

                if full and part: return

        if not full: print("----------Nenasla sa kompletna komunikacia--------")
        if not part: print("----------Nenasla sa nekompletna komunikacia------")

# ukladanie TCP komunikacie
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

# Automat na kontrolu TCP ukoncenia
class FinTCPAutomat:

    def __init__(self):
        self.status = 0

    def updateAutomat(self, packet):
        if self.status == 0 and (packet.packet[47] & int("11", 16))  == 17 : #FIN, ACK
            self.status = 1
            return
        if self.status == 0 and (packet.packet[47] & int("01", 16)) == 1: #FIN
            self.status = 2
            return
        if (packet.packet[47] & int("14", 16)) == 20: #RST,ACK
            self.status = 6.1
            return
        if (packet.packet[47] & int("04", 16)) == 4: #RST
            self.status = 6.1
            return


        if self.status == 1 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'):#FIN,ACK -> ACK
            self.status = 1.1
            return
        if self.status == 1.1 and (packet.packet[47] & int("11", 16)) == 17: #FIN,ACK -> ACK -> FIN,ACK
            self.status = 1.2
            return
        if self.status == 1.2 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'): #FIN,ACK -> ACK -> FIN,ACK -> ACK
            self.status = 6 #DONE
            return

        if self.status == 1 and (packet.packet[47] & int("11", 16)) == 17:#FIN,ACK -> FIN,ACK
            self.status = 1.11
            return
        if self.status == 1.11 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'): #FIN,ACK -> FIN,ACK -> ACK
            self.status = 1.12
            return
        if self.status == 1.12 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'): #FIN,ACK -> FIN,ACK -> ACK -> ACK
            self.status = 6 #DONE
            return

        if self.status == 2 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'): #FIN -> ACK
            self.status = 2.1
            return
        if self.status == 2.1 and (packet.packet[47] & int("01", 16)) == 1: #FIN -> ACK -> FIN
            self.status = 2.2
            return
        if self.status == 2.2 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'): #FIN -> ACK -> FIN -> ACK
            self.status = 6 #DONE
            return

        if self.status == 2 and (packet.packet[47] & int("04", 16)) == 4: #FIN -> RST
            self.status = 6.1
            return

        if self.status == 6.1 and (decToHex(packet.packet[47]).lower() == '10' or decToHex(packet.packet[47]).lower() == '18'): #..RST -> ACK?
            self.status = 6
            return

def decToHex(n1):
    x = hex(n1)[2:]
    if len(x) == 1:
        x='0'+x
    return x
