
"""class used to process the client"""

__author__ = "100488290"
__status__ = "Development"

import selectors
import queue
import SMTPClientEncryption
import time
import random
from threading import Thread
import hashlib


class Module (Thread):

    def __init__(self, sock, addr):
        """initialization and definition of the variables"""
        Thread.__init__(self)

        self._selector = selectors.DefaultSelector()
        self._sock = sock
        self._addr = addr
        self._incoming_buffer = queue.Queue()                              # contains the messages from the server
        self._outgoing_buffer = queue.Queue()                              # contains the messages to send to the server

        self._base = random.randint(1, 1000)
        self._modulus = random.randint(5, 45)

        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self._selector.register(self._sock, events, data=None)
        self._running = True

        self._isData = True
        self._commands = ["NOOP", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "LOGI", "IMSG"]  # list of allowed commands
        self._current_state = "Waiting for LOGIN"                                  # the state in which is the client
        self.server_response = ""                                                  # server response to the client input
        self.message_received = ""

        # encryption variables
        self.encryption = SMTPClientEncryption.Encryption(self._base, self._modulus)  # import the encryption
        self.encryption.toggle_enable()                                               # active Encryption
        self.encryption.set_method("caesar")                                        # set the type of encryption
        self.server_public_key = None
        self._is_key = True
        self.client_public_key = self.encryption.generate_public_key()      # generate the public key to send to server
        self.send_key(self.client_public_key)                               # send the client public key to the server
        self.first_message = True

        # timer variables
        self._countdown = 60

        # login variables
        self._username = ""
        self._password = ""
        self._user_login_details = {}
        self._is_login = False
        self._user_online = ""
        self._user_not_online = ""

    def get_login_state(self):
        return self._is_login

    def is_running(self):
        """check if the client is running or not"""
        return self._running

    def run(self):
        """entry point for thread"""
        try:
            # negotiate the base and the modulus with the server to get the shared key
            encoded = (str(self._base) + ":"+str(self._modulus)).encode()
            self._sock.send(encoded)
            print("Base: " + str(self._base) + "   " + "Modulus: " + str(self._modulus))
            time.sleep(0.1)

            # read and write from and to the server while the client is running
            while self._running:
                events = self._selector.select(timeout=1)
                for key, mask in events:
                    message = key.data
                    try:
                        if mask & selectors.EVENT_READ:
                            self.read()
                        if mask & selectors.EVENT_WRITE and not self._outgoing_buffer.empty():
                            self.write()
                    except Exception:
                        self.close()

                # Check for a socket being monitored to continue.
                if not self._selector.get_map():
                    break
        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
        finally:
            self._selector.close()

    def read(self):
        """read the message from the server

        note: if the encryption is diffie hellman, the first message received is the public key from the server
        """
        try:
            # perform only for the first message received (the server public key)
            if self._is_key:
                data = self._sock.recv(4096)
                self.server_public_key = data.decode()
                shared_key = self.encryption.generate_shared_key(self.server_public_key)
                print("\rThe shared key is: " + str(shared_key))
                if self.encryption.method == "caesar":
                    self.encryption.set_caesar_key(shared_key)
                elif self.encryption.method == "vigenere":
                    self.encryption.set_vigenere_key(shared_key)
            # perform for the following messages received
            else:
                data = self._sock.recv(4096)

        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            # decode and decrypt the message from the server
            if data:
                # perform only if the method is diffie hellman
                if self._is_key:
                    self._is_key = False
                else:
                    self._incoming_buffer.put(self.encryption.decrypt(data.decode()))
            else:
                raise RuntimeError("Peer closed.")

    def write(self):
        """send the message to the server"""
        try:
            message = self._outgoing_buffer.get_nowait()

        except Exception:
            message = None

        if message:
            print("sending ", repr(message), "to", self._addr)
            if self.first_message:
                print("Enter a string: ")
                self.first_message = False
            try:
                sent = self._sock.send(message)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass

    def username_validity(self, value):
        self.create_message(value)
        self.print_server_response()
        if self.server_response == "250 OK User Accepted":
            self._username = value
            return True
        else:
            return False

    def password_validity(self, password):
        salt = b'F\xc8\xe8\xeb\xa9!\xda\xe8K5;y\xb3\xdbI8;J7\xdawE\xd5\x18\xb4p\x8b\xb7Q\xb8\x0f\x94'  # A new salt for this user
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        self._user_login_details[self._username] = {  # Store the salt and key
            'salt': salt,
            'key': key
        }
        self.create_message(key)
        self.print_server_response()
        if self.server_response == "250 OK Password Accepted":
            print("LOGIN SUCCESSFUL")
            self._password = password
            self._is_login = False
            return True
        else:
            return False

    def create_message(self, content):
        """encoding and encryption of the message"""
        msg_encrypted = self.encryption.encrypt(content)                    # encrypt the message
        msg_encoded = msg_encrypted.encode()                                # encode the message
        self._outgoing_buffer.put(msg_encoded)

    def send_key(self, content):
        """encoding of the public key of the client"""
        str_key = str(content)
        encode_key = str_key.encode()                                       # encode the key
        self._outgoing_buffer.put(encode_key)

    def validate_input(self, user_input):
        """check the validity of user input"""

        # close the connection with the server if the command is QUIT
        if user_input == "QUIT":
            self.create_message(user_input)
            self._running = False
            return

        # perform only if the client is in the DATA state
        if self._current_state == "DATA":
            # if the input is "." end the input of the email content and start a new mail process
            if user_input == ".":
                self.create_message(user_input)
                self.print_server_response()
                self._current_state = "Waiting for MAIL or IMSG"
            # if it not "." only send the message to the server
            else:
                self.create_message(user_input)

        elif self._current_state == "IMESSAGE":
            # if the input is "." end the input of the imessage content and start a new process
            if user_input == ".":
                self.create_message(user_input)
                self.print_server_response()
                self._current_state = "Waiting for MAIL or IMSG"
            # if it not "." only send the message to the server
            else:
                self.create_message(user_input)

        # if the input of the client is not "DATA" perform the other tasks
        elif user_input != "DATA":
            # check if the command is of the correct length, that is 4
            parts = user_input.split(" ")
            command = parts[0]
            if len(command) != 4:
                print("502 The length of the command should be 4")

            #  check if the command is one of the allowed commands
            elif command not in self._commands:
                print("500 Unknown command")

            # LOGIN PROCESS
            elif self._current_state == "Waiting for LOGIN":
                if command == "LOGI" or command == "QUIT":
                    self.create_message(user_input)
                    self.print_server_response()

                    # if the server accepted the HELO, go to the next step state (HELO)
                    if self.server_response == "250 OK Start Login":
                        self._is_login = True
                        self._current_state = "Waiting for HELO"

                elif command in self._commands:
                    print("502 The command is not valid for this state")

            # HELO process
            elif self._current_state == "Waiting for HELO":
                if command == "HELO" or command == "NOOP" or command == "QUIT":
                    self.create_message(user_input)
                    self.print_server_response()

                    # if the server accepted the HELO, go to the next step state (MAIL)
                    if user_input != "NOOP":
                        if self.server_response == "250 OK":
                            self._current_state = "Waiting for MAIL or IMSG"
                            print("Valid commands are MAIL, IMSG, NOOP and QUIT")
                elif command in self._commands:
                    print("502 The command is not valid for this state")

            # MAIL/IMESSAGE process
            elif self._current_state == "Waiting for MAIL or IMSG":
                if command == "MAIL" or command == "NOOP" or command == "QUIT" or command == "IMSG":
                    self.create_message(user_input)
                    self.print_server_response()
                    try:
                        front_part, path = user_input.split(":")
                        self._user_online = "250 OK " + path[1:-1] + " is online"
                        self._user_not_online = "400 User " + path[1:-1] + " not online"
                        # if the server has validated the sender email, go to the next step state (RCPT)
                    except:
                        pass

                    if user_input != "NOOP":
                        if self.server_response == "250 OK":
                            self._current_state = "Waiting for RCPT"
                            print("Valid commands are RCPT, NOOP and QUIT")
                        elif self.server_response == self._user_online or self.server_response == self._user_not_online:
                            print("Start input of Imessage: ")
                            self._current_state = "IMESSAGE"
                            return
                elif command in self._commands:
                    print("502 The command is not valid for this state")
                    print("Valid commands are MAIL, NOOP and QUIT")

            # RCPT process
            elif self._current_state == "Waiting for RCPT":
                if command == "RCPT" or command == "NOOP" or command == "QUIT":
                    self.create_message(user_input)
                    self.print_server_response()

                    # if the server has validated the recipient email, go to the next step state (RCPT or DATA)
                    if user_input != "NOOP":
                        if self.server_response == "250 OK":
                            self._current_state = "Waiting for RCPT or DATA"
                            print("Valid commands are RCPT, DATA, NOOP and QUIT")
                elif command in self._commands:
                    print("502 The command is not valid for this state")
                    print("Valid commands are RCPT, NOOP and QUIT")

            # RCPT or DATA process. the user can insert another recipient or start the email content population
            elif self._current_state == "Waiting for RCPT or DATA":
                if command == "RCPT" or command == "NOOP" or command == "QUIT" or command == "DATA":
                    self.create_message(user_input)
                    self.print_server_response()

                    # if the server confirmed the starting of the email content, go to the next step state (DATA)
                    if self.server_response == "354 insert the content of the email":
                        self._current_state = "DATA"
                elif command in self._commands:
                    print("502 The command is not valid for this state")
                    print("Valid commands are RCPT, DATA, NOOP and QUIT")
            else:
                pass

        # Change the state to DATA only if the current state is "Waiting for RCPT or DATA"
        elif user_input == "DATA" and self._current_state == "Waiting for RCPT or DATA":
            self._current_state = "DATA"
            self.create_message("DATA")
            self.print_server_response()
        else:
            print("502 The command is not valid for this state")

    def print_server_response(self):
        """print the response received from the server regarding the input of the client"""
        time.sleep(0.3)
        # keep printing the message from the server until the incoming messages buffer is not empty
        while not self._incoming_buffer.empty():
            message = self._incoming_buffer.get()
            self.server_response = message

            # separate the first 3 characters (response code) from the rest of the message
            header_length = 3
            if len(message) >= header_length:
                print(message[0:header_length], message[header_length:])

    def close(self):
        """close the connection with the server"""
        print("\nclosing connection to", self._addr)
        try:
            self._selector.unregister(self._sock)
        except BlockingIOError:
            pass
        try:
            self._sock.close()
        except OSError as e:
            pass
        finally:
            # Delete reference to socket object for garbage collection
            self._sock = None
            self._running = False
