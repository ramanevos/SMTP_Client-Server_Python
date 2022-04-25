
"""class containing the threaded client"""

__author__ = "100488290"
__status__ = "Development"

import socket
import selectors
import SMTPClientLib
import time


class NWSThreadedClient:
    def __init__(self, host="127.0.0.1", port=12347):
        """initialization"""
        if __debug__:
            print("NWSThreadedClient.__init__", host, port)

        # Network components
        self._host = host
        self._port = port
        self._listening_socket = None
        self._selector = selectors.DefaultSelector()
        self._module = None
        self._running = True

        # login variables
        self._is_login = True
        self._is_username = True
        self._is_password = False

    def start_connection(self, host, port):
        """begin the connection with the server in non blocking mode"""
        addr = (host, port)
        print("starting connection to", addr)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)                                               # set the client in non blocking mode
        sock.connect_ex(addr)                                                 # connect with server

        self._module = SMTPClientLib.Module(sock, addr)
        self._module.start()

    def run(self):
        """entry point for the thread"""
        self.start_connection(self._host, self._port)

        # run the client until the connection is closed
        while self._running:
            if self._module.get_login_state():
                if self._is_username:
                    username = input("Enter your username: ")
                    if self._module.username_validity(username):
                        self._is_username = False
                        # self._is_password = True
                else:
                    password = input("Enter the password: ")
                    if self._module.password_validity(password):
                        self._is_login = False
            else:
                time.sleep(0.1)
                user_input = input("Enter a string: ")                         # input of the client
                self._module.validate_input(user_input)                        # validate and process the client input
            self._running = self._module.is_running()


if __name__ == "__main__":
    client = NWSThreadedClient()
    client.run()
