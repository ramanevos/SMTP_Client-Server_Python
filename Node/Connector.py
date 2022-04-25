

# A connector connects from this node to another node service and does something.
class Connector():
    def __init__(self):
        pass

    def connectTo(self, ip, port):
        pass

    def sendData(self, message):
        pass

    def readData(self):
        return None

    def closeConnector(self):
        pass

# A transient connector connects sends data, receives one or more responses, then terminates
class transientConnector(Connector):
    def __init__(self):
        Connector.__init__(self)
        pass

# A streaming connector opens a two way connection that must be terminated directly
class streamingConnector(Connector):
    def __init__(self):
        Connector.__init__(self)
        pass