
"""class containing the threaded server"""

__author__ = "100488290"
__status__ = "Development"

import socket
import selectors
import SMTPServerLib


class NWSThreadedServer:
    def __init__(self, host="127.0.0.1", port=12347):
        """initialization of the variables"""
        if __debug__:
            print("NWSThreadedServer.__init__", host, port)

        # Network components
        self._host = host
        self._port = port
        self._listening_socket = None
        self._selector = selectors.DefaultSelector()

        # Processing Components
        self._modules = []
        self._lastMessageTime = None

        # clear the content of the file containing the pending messages
        file = open("queue_imessages.txt", "r+")
        file.truncate(0)
        file.close()

        # Imessage variables
        self._UserList = []
        self._username_list = []
        self._queuedMessages = []

    def get_connected_users_list(self):
        """return the list or connected users"""
        return self._username_list

    def add_user(self, username, module):
        """add the client to the list of connected users"""
        self._UserList.append({"user": username, "mod": module})
        self._username_list.append(username)
        print("list of connected users: " + str(self._UserList))

    def log_off(self, username, module):
        """remove the client from the list of connected users"""
        self._UserList.remove({"user": username, "mod": module})
        self._username_list.remove(username)
        pass

    def message_user(self, username, message):
        """send a Imessage to a connected user or write it on disk for later retrieval if the receiver is offline"""
        message_found = False

        # if the receiver is connected send the message to it
        for item in self._UserList:
            name = item["user"]
            module = item["mod"]
            if name == username:
                module.create_message("250 IMSG: " + message)
                return

        # if the receiver is offline write the message on disk
        if not message_found:
            f = open("queue_imessages.txt", "a")
            message_to_queue = str(username + "~" + str(message) + "\n")
            f.write(message_to_queue)
            f.close()
            print(str(username) + " not online, saving message")
            return

    def retrieve_message(self, username):
        """check if the client has any message in the queue received when it was, if yes print them"""
        # open the file containing the pending messages
        f = open("queue_imessages.txt", "r")
        available_messages = f.readlines()
        retrieved_messages = []

        # check if the connected client has any message pending in the queue
        for msg in available_messages:
            if msg:
                name, message = msg.split("~")
                if name == username:
                    self._queuedMessages.append(msg)
                    retrieved_messages.append(message[:-1])
        f.close()

        # remove the messages that has been successfully delivered from the file
        new_file = open("queue_imessages.txt", "w")
        for y in available_messages:
            if y not in self._queuedMessages:
                new_file.write(y)
        new_file.close()

        # if any message for the client has been found in the queue, return it
        if retrieved_messages:
            return retrieved_messages

    def configure_server(self):
        """configuration of the sockets of the server"""
        self._listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Avoid bind() exception: OSError: [Errno 48] Address already in use
        self._listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listening_socket.bind((self._host, self._port))           # bind the port and host to the socket
        self._listening_socket.listen()                                 # listen to the incoming connection

        print("listening on", (self._host, self._port))
        self._listening_socket.setblocking(False)
        self._selector.register(self._listening_socket, selectors.EVENT_READ, data=None)

    def accept_wrapper(self, sock):
        """accept the connection with the client"""
        conn, addr = sock.accept()                                      # should be ready to read
        print("accepted connection from", addr)
        conn.setblocking(False)                                         # non blocking mode
        module = SMTPServerLib.Module(conn, addr, self)                 # import SMTPServerlib
        self._modules.append(module)
        module.start()

    def run(self):
        """Entry point for the thread"""
        self.configure_server()

        try:
            while True:
                events = self._selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self.accept_wrapper(key.fileobj)
                    else:
                        pass
        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
        finally:
            self._selector.close()


if __name__ == "__main__":
    server = NWSThreadedServer()
    server.run()
