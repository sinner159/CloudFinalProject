class Machine():

    def __init__(self, ip, interface, mac, name):
        self.ip = ip
        self.interface = interface
        self.mac = mac
        self.name = name

        
class Client(Machine):

    def __init__(self, ip, interface, mac,name,cookie, is_suspicious=False,is_attacker=False):
        super().__init__(ip, interface, mac, name)
        self.is_suspicious = is_suspicious
        self.is_attacker = is_attacker
        self.cookie = cookie

class Host(Machine):
    
    def __init__(self, ip, interface, mac,name, is_target=False):
        super().__init__(ip, interface, mac, name)
        self.is_target = is_target