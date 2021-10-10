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

