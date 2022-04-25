import Connector
import Service

class Node:
    def __init__(self):
        self.serviceList = []

    def createService(self, port, host, name):
        temp = Service.Service(port, host)
        if temp:
            self.serviceList.append((temp,name))
            return True
        return False

    def getService(self, name):
        pass

    def deleteService(self, name):
        pass


if __name__ == "__main__":
