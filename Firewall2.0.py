ips_autoriser = ['192.168.1.1', '192.168.1.2']
class Regle:
    def __init__(self,port,protocol,action):
         self.port=port
         self.ipadress=ips_autoriser
         self.protocol=protocol
         self.action=action

    def ip_adress(self,ip):
        ipadress,port,protocol=ip
        if self.protocol in self.protocol!= protocol:
            return False
        if self.port != port:
            return False
        if self.ipadress in self.ipadress != ipadress:
            return False
        return True
        

class Firewall:
    def __init__(self):
        self.regle=[]

    def ajouter_ip(self,ip):
        self.regle.append(ip)
    def retirer_ip(self,ip):
        if ip in self.regle:
            self.regle.remove(ip)
    
    def verifier_paquet(self, paquet):
        for regle in self.regle:
            if regle.ip_adress(paquet):
                return regle.action == "autoriser"
        return False
class Tracepacket:
    def __init__(self, ipadress, port, protocol):
        self.ipadress = ipadress
        self.port = port
        self.protocol = protocol

    def en_paquet(self):
        return (self.ipadress, self.port, self.protocol)

if __name__ == "__main__":
    pare_feu = Firewall()

regle_autorisation = Regle(port=80, protocol="TCP", action="autoriser")
regle_blocage = Regle(port=22, protocol="TCP", action="bloquer")
pare_feu.ajouter_ip(regle_autorisation)
pare_feu.ajouter_ip(regle_blocage)

paquet1 = Tracepacket(ipadress="192.168.1.1", port=80, protocol="TCP")
paquet2 = Tracepacket(ipadress="192.168.1.2", port=22, protocol="TCP")


print(f"Paquet 1 autorisé : {pare_feu.verifier_paquet(paquet1.en_paquet())}")
print(f"Paquet 2 autorisé : {pare_feu.verifier_paquet(paquet2.en_paquet())}")