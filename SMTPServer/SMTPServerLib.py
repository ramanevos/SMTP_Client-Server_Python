
"""class used to process the individual connection for each connected client"""

__author__ = "100488290"
__status__ = "Development"

import selectors
import queue
import SMTPServerEncryption
import re
import time
import sys

from threading import Thread


class Module(Thread):
    def __init__(self, sock, addr, server):
        """initialization of all the variables"""
        Thread.__init__(self)

        self._selector = selectors.DefaultSelector()
        self._sock = sock                                             # socket of the client connected
        self._addr = addr                                             # address of the client connected

        self._incoming_buffer = queue.Queue()                         # queue for the message coming from the clients
        self._outgoing_buffer = queue.Queue()                         # queue for the message to be sent to the clients

        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self._selector.register(self._sock, events, data=None)
        self._running = True
        self._currentState = "Encryption"

        # data variables
        self._sender = ""
        self._recipients = []
        self._data = ""
        self._count_recipients = 0

        self._server = server

        # encryption variables
        self.encryption = SMTPServerEncryption.Encryption()           # import the encryption class
        self.encryption.set_method("caesar")                        # Set the type of encryption
        self._client_public_key = None                                # public key of the client for diffie hellman
        self.server_public_key = None                                 # public key of the server for diffie hellman
        self.is_key = False
        self._base = 0                                                # base value for diffie hellman
        self._modulus = 0                                             # modulus value for diffie hellman

        # timer variables
        self._countdown = 600
        self._timeout = True

        # login variables
        self._login_process = False
        self._usernames = []
        self._passwords = []
        self._is_username = False
        self._is_password = False
        self._username_position = None
        self._password_position = None
        self._position_count = 0
        self._connected_users = []
        self._user_is_connected = False
        self._connected_user = ""
        self._recipient_user = ""

    def run(self):
        """entry point for the thread. Negotiate the keys with the client and run the timer"""
        try:
            message = self._sock.recv(4096)
            self._base, self._modulus = message.decode().split(":")
            self.encryption.set_base_mod(self._base, self._modulus)
            print("Base: " + str(self._base) + "   " + "Modulus: " + str(self._modulus))
            # perform only if the encryption method is diffie hellman
            self._client_public_key = None
            # generate the public key to send to the clients

            self.server_public_key = self.encryption.generate_public_key()
            self.send_key(self.server_public_key)
            self.is_key = True

            self.encryption.toggle_enable()  # Active Encryption

            while self._running:

                # timer
                if self._timeout:
                    if self._countdown != 0:
                        countdown = self._countdown % 10
                        if countdown == 0:
                            seconds = int(self._countdown/10)
                            # print the seconds left before the closure of the connection
                            print("\r{:2d} seconds remaining for ".format(seconds)+str(self._addr))
                        sys.stdout.flush()
                        time.sleep(0.1)
                        self._countdown -= 1

                    # close the connection if the timer reaches 0 seconds
                    else:
                        print("\nTIMEOUT")
                        self._running = False
                        self.close()
                        return

                events = self._selector.select(timeout=None)
                for key, mask in events:
                    try:
                        if mask & selectors.EVENT_READ:
                            self._read()                              # read the message received from the client
                        if mask & selectors.EVENT_WRITE and not self._outgoing_buffer.empty():
                            self._write()                             # write the message to send to the client
                    except Exception:
                        self.close()
                if not self._selector.get_map():
                    break

        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
        finally:
            self._selector.close()

    def _read(self):
        """read the message that comes from the client

        note: if the encryption is diffie hellman, the first message received is the public key from the client
        """
        try:
            # perform only during the negotiation of the keys
            if self.is_key:
                data = self._sock.recv(4096)
                self._client_public_key = data.decode()
                shared_key = self.encryption.generate_shared_key(self._client_public_key)
                sys.stdout.write("\rThe shared key is: " + str(shared_key) + "\n")
                self.is_key = False
                if self.encryption.method == "caesar":
                    self.encryption.set_caesar_key(shared_key)
                elif self.encryption.method == "vigenere":
                    self.encryption.set_vigenere_key(shared_key)
            # perform for the following messages received
            else:
                data = self._sock.recv(4096)

        except Exception:
            try:
                self._server.log_off(self._connected_user, self)
            except:
                pass
            print("blocked")
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            # decrypt and decode the message from the client
            if data:
                self._incoming_buffer.put(self.encryption.decrypt(data.decode()))
            else:
                raise RuntimeError("Peer closed.")

        self.process_response()

    def _write(self):
        """send the message to the client"""
        try:
            message = self._outgoing_buffer.get_nowait()
        except Exception:
            message = None

        if message:
            print("sending", repr(message), "to", self._addr)
            try:
                sent = self._sock.send(message)
            except Exception:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass

    def create_message(self, content):
        """encoding and encryption of the message"""
        msg_encrypted = self.encryption.encrypt(content)              # encrypt the message
        msg_encoded = msg_encrypted.encode()                          # encode the message
        self._outgoing_buffer.put(msg_encoded)

    def send_key(self, content):
        """encoding of the public key of the client"""
        str_key = str(content)
        encode_key = str_key.encode()                                 # encode the key
        self._outgoing_buffer.put(encode_key)

    def process_response(self):
        """Process the response for message received from the client"""
        message = self._incoming_buffer.get()                         # get the input from the client

        # if a message is received, restart the timer
        if self._timeout:
            if message:
                self._countdown = 600

        # The message is split and the first word, that is the CMD word, is stored in a variable
        parts = message.split(" ")
        command = parts[0]

        # LOGIN process
        if self._currentState == "Waiting for LOGIN":
            allowed_commands = ["LOGI", "NOOP", "QUIT"]
            if command in allowed_commands:
                self.command_process(command, message)
                if command == "LOGI":
                    self._login_process = True
                return
            elif self._login_process:
                self.command_process(command, message)
                return
            else:
                self.create_message("502 Command not valid for this state")
                return

        # HELO process
        elif self._currentState == "Waiting for HELO":
            allowed_commands = ["HELO", "NOOP", "QUIT"]
            if command not in allowed_commands:
                self.create_message("502 Command not valid for this state")
                return
            else:
                self.command_process(command, message)
                self._currentState = "Waiting for MAIL or IMSG"

        # MAIL/IMSG PROCESS
        elif self._currentState == "Waiting for MAIL or IMSG":
            allowed_commands = ["MAIL", "NOOP", "QUIT", "IMSG"]
            if command not in allowed_commands:
                self.create_message("502 Command not valid for this state")
                return
            else:
                self.command_process(command, message)

        # IMESSAGE process
        elif self._currentState == "IMESSAGE":
            # start the mail content population if the previous command received is data
            # the "." ends the email content. Write on the disk the Sender, Recipients and email data
            if command == ".":
                self._data += message
                self._server.message_user(self._recipient_user, self._data)
                self._data = ""
                self._currentState = "Waiting for MAIL or IMSG"
                self.create_message("250 OK IMSG process completed. Insert a new MAIL/IMSG or QUIT the program")
                return

            # add the new message to the previous
            else:
                self._data += " " + message
                return

        # RCPT process
        elif self._currentState == "Waiting for RCPT":
            allowed_commands = ["RCPT", "NOOP", "QUIT"]
            if command not in allowed_commands:
                self.create_message("502 Command not valid for this state")
                return
            else:
                self.command_process(command, message)
        elif self._currentState == "Waiting for RCPT or DATA":
            allowed_commands = ["RCPT", "DATA", "NOOP", "QUIT"]
            if command not in allowed_commands:
                self.create_message("502 Command not valid for this state")
                return
            self.command_process(command, message)
        elif self._currentState == "DATA":
            # start the mail content population if the previous command received is data
            # the "." ends the email content. Write on the disk the Sender, Recipients and email data
            if command == ".":
                self._data += message + ""
                f = open("mail.txt", "a")
                export_message = "Sender: " + self._sender + "\n"
                f.write(export_message)

                # check the number of recipients and write each of them on the disk
                for x in self._recipients:
                    self._count_recipients += 1
                    export_message = "Recipient " + str(self._count_recipients) + ": " + str(x) + "\n"
                    f.write(export_message)

                export_message = "Data: " + self._data + "\n\n"
                f.write(export_message)
                f.close()

                # clear all the fields for a new email
                self._sender = ""
                self._recipients = []
                self._count_recipients = 0
                self._data = ""
                self._currentState = "Waiting for MAIL or IMSG"
                self.create_message("250 OK Mail process completed. Insert a new MAIL/IMSG or QUIT the program")
                return

            # add the new message to the previous
            else:
                self._data += " " + message
                return
        elif self._currentState == "Encryption" and not self.is_key:
            self._currentState = "Waiting for LOGIN"

        elif self._currentState == "Encryption":
            return
        else:
            pass

    def command_process(self, command, message):
        """A specific task is performed depending on the command from the client"""
        if message == "QUIT":
            self.close()
            return

        if message == "LOGI":
            if not self._login_process:
                self._is_username = True
                f = open("login.txt", "r")
                account_counter = 0
                available_accounts = f.readlines()
                current_account = 0

                for i in available_accounts:
                    if i:
                        account_counter += 1
                while current_account < account_counter:
                    user = available_accounts[current_account]
                    username, password = user.split(" ")
                    if password[-1] == "\n":
                        password = password[:-1]
                    self._usernames.append(username)
                    self._passwords.append(password)
                    current_account += 1
                f.close()

                self.create_message("250 OK Start Login")
                return

        if self._is_username:
            if message in self._usernames:
                for username in self._usernames:
                    if message == self._usernames[self._position_count]:
                        self._username_position = self._position_count
                    self._position_count += 1
                self._connected_user = message
                self.create_message("250 OK User Accepted")
                self._is_username = False
                self._is_password = True

                return
            else:
                self.create_message("521 username doesn't exist, try again")
                return

        if self._is_password:
            if message in self._passwords:
                if message == self._passwords[self._username_position]:
                    # if the login is successful check if there are any pending messages in the queue
                    queue_messages = self._server.retrieve_message(self._connected_user)
                    if queue_messages is not None:
                        # send the pending messages to the client
                        for msg in queue_messages:
                            self.create_message("250 IMSG: " + str(msg))
                    time.sleep(0.1)
                    self.create_message("250 OK Password Accepted")
                    print("LOGIN SUCCESSFUL FOR ", self._addr)
                    self._server.add_user(self._connected_user, self)
                    self._currentState = "Waiting for HELO"
                    self._is_password = False

                else:
                    self.create_message("521 Wrong Password, try again")
            else:
                self.create_message("521 Wrong Password, try again")

        elif command == "NOOP":
            self.create_message("250 OK")

        # print the connected client address and send a confirmation message to it
        elif command == "HELO":
            self.create_message("250 OK")
            print("\rHello", self._addr)

            # perform the validation of the sender's email
        elif command == "IMSG":
            if message[-1] == ":":
                self.create_message("504 Missing information from IMSG command.")
            else:
                try:
                    front_part, path = message.split(":")
                    # example: IMSG TO:<university@gmail.com>
                    # front_part: IMSG TO
                    # path: <university@gmail.com>

                except Exception:
                    self.create_message("504 incorrect format for IMSG command.")
                    return

                # Divide the part before the ":"
                command_part, from_part = front_part.split(" ")
                # example: IMSG TO
                # command_part: IMSG
                # from_part: TO

                # check if the IMSG command is followed from "TO"
                if from_part != "TO":
                    self.create_message("504 Invalid command format, TO: must follow IMSG")

                # check if the email is included in the brackets "<" and ">"
                elif path[0] == "<" and path[-1] == ">":
                    # get the list of connected users
                    connected_users = self._server.get_connected_users_list()

                    if path[1:-1] in connected_users:
                        self._recipient_user = path[1:-1]
                        print_user_online = "250 OK " + path[1:-1] + " is online"
                        self.create_message(print_user_online)
                        self._currentState = "IMESSAGE"
                    elif path[1:-1] in self._usernames and path[1:-1] not in self._connected_users:
                        self._recipient_user = path[1:-1]
                        self.create_message("400 User " + path[1:-1] + " not online")
                        self._currentState = "IMESSAGE"
                    else:
                        self.create_message("500 User doesn't exist")
                else:
                    self.create_message("510 Brackets missing or in wrong position")

        # perform the validation of the sender's email
        elif command == "MAIL":
            if message[-1] == ":":
                self.create_message("504 Missing information from MAIL command.")
            else:
                try:
                    front_part, path = message.split(":")
                    # example: MAIL FROM:<university@gmail.com>
                    # front_part: MAIL FROM
                    # path: <university@gmail.com>

                except Exception:
                    self.create_message("504 incorrect format for MAIL command.")
                    return

                # Divide the part before the ":"
                command_part, from_part = front_part.split(" ")
                # example: MAIL FROM
                # command_part: MAIL
                # from_part: FROM

                # check if the MAIL command is followed from "FROM"
                if from_part != "FROM":
                    self.create_message("504 Invalid command format, FROM: must follow MAIL")

                # check if the email is included in the brackets "<" and ">"
                elif path[0] == "<" and path[-1] == ">":
                    if self.is_valid_domain(path[1:-1]):
                        self._sender = path
                        self.create_message("250 OK")
                        self._currentState = "Waiting for RCPT"
                    else:
                        self.create_message("510 Invalid email address")
                else:
                    self.create_message("510 Brackets missing or in wrong position")

        # perform the validation of the recipients' emails
        elif command == "RCPT":
            if message[-1] == ":":
                self.create_message("504 Missing information from RCPT command.")
            else:
                try:
                    front_part, path = message.split(":")
                except Exception:
                    self.create_message("504 incorrect format for RCPT command.")
                    return
                command_part, from_part = front_part.split(" ")

                # check if the RCPT command is followed by "TO"
                if from_part != "TO":
                    self.create_message("504 Invalid command format, TO: must follow RCPT")
                    return

                # check if the email is included in the brackets "<" and ">"
                if path[0] == "<" and path[-1] == ">":
                    if self.is_valid_domain(path[1:-1]):              # validate the email address
                        self.create_message("250 OK")
                        self._currentState = "Waiting for RCPT or DATA"
                        self._recipients.append(path)                 # add the recipient to the list of recipients
                    else:
                        self.create_message("510 Invalid email address")
                else:
                    self.create_message("510 Brackets missing or in wrong position")

        # close the connection with the client
        elif command == "QUIT":
            print("Connection Closing")
            self.close()

        # order to the client to start the email content population
        elif command == "DATA":
            self._currentState = "DATA"
            self.create_message("354 insert the content of the email")
        else:
            pass

    def is_valid_domain(self, path):
        """check if the email inserted is a valid email format"""
        regex = '\\w+[.|\\w]\\w+@\\w+[.]\\w+[.|\\w+]\\w+'
        if re.search(regex, path):
            return True

    def close(self):
        """close the connection with the client"""
        print("closing connection to", self._addr)
        try:
            # remove the client from the connected users
            self._server.log_off(self._connected_user, self)
        except:
            pass
        try:
            self._selector.unregister(self._sock)
        except BlockingIOError as e:
            pass
        try:
            self._sock.close()
        except OSError as e:
            pass
        finally:
            # Delete reference to socket object for garbage collection
            self._sock = None
        self._running = False
