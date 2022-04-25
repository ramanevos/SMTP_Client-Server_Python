import Connector
from threading import Thread

class Service(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.serviceList = []

    def createListenerSocket(self, port, host):
        #
        """
        :param port:
        :param host:
        :return:
        Create a listener socket on the port and host specified, runs the specified service e.g. distribvution of files
        """
        pass

    def processMessage(self):
        """
        Pretty much networks and security in here: but with the option to create connectors to go and get data from other services
        Think of this a lot like building the web api from App Dev
        :return:
        """

        pass

    def run(self):
        # while the service is running:
            # accept incoming connections and add to lists to service (select)
            # service incoming connections
        pass