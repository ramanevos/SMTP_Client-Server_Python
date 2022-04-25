
"""class used to encrypt/decrypt the server"""

__author__ = "100488290"
__status__ = "Development"

import random


class Encryption:
    def __init__(self):
        """Encryption variables initialization"""
        # public variables
        self.method = None

        # protected variables
        self._enabled = False
        # caesar variables
        self._caesar_key = 0
        # vigenere variables
        self._create_keyword = True
        self._alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!£$%^&*()-+={}[]:;@'<,>.?/\\# "
        self._vigenere_key = 0
        self.vigenere_keyword = ""

        # diffie hellman variables
        self._base = 1
        self._mod = 1
        self._private_key = random.randrange(1, 10)
        self._shared_key = None
        self._public_key = None

    def set_base_mod(self, base, modulus):
        """assign a value to the base and modulus variables"""
        self._base = int(base)
        self._mod = int(modulus)

    def toggle_enable(self):
        """enable the encryption/decryption process"""
        self._enabled = not self._enabled
        return self._enabled

    def get_base(self):
        """assign the value for the base for diffie hellman"""
        return self._base

    def get_mod(self):
        """assign the value for the modulus for diffie hellman"""
        return self._mod

    def set_caesar_key(self, key):
        """create a caesar key"""
        try:
            self._caesar_key = int(key)
        except TypeError:
            self._caesar_key = 0
            return None

    def set_vigenere_key(self, key):
        """create a vigenere key"""
        try:
            self._vigenere_key = int(key)
        except TypeError:
            self._vigenere_key = 0
            return None

    def set_method(self, method):
        """choose the encryption method to use"""
        if method.lower() == "caesar":
            self.method = "caesar"
        elif method.lower() == "vigenere":
            self.method = "vigenere"
        elif method.lower() == "hellman":
            self.method = "hellman"
        else:
            self.method = None

    def encrypt(self, message) -> str:
        """encrypt the message using the chosen encryption method"""
        if self._enabled:
            if self.method == "caesar":
                return self._caesar_cipher_encrypt(message)
            elif self.method == "vigenere":
                return self._vigenere_square_encrypt(message)
            elif self.method == "hellman":
                return self._diffie_hellman_encrypt(message)
        return message

    def decrypt(self, message) -> str:
        """decrypt the message using the chosen encryption method"""
        if self._enabled:
            if self.method == "caesar":
                return self._caesar_cipher_decrypt(message)
            elif self.method == "vigenere":
                return self._vigenere_square_decrypt(message)
            elif self.method == "hellman":
                return self._diffie_hellman_decrypt(message)
        return message

    def _caesar_cipher_encrypt(self, message) -> str:
        """encryption using caesar cipher

           the operation with the module % is used to keep the output value between 32 and 126, to get only
           valid ascii numbers
           note: the last ascii number (127) that represent the delete button is not included
        """
        try:
            message = str(message)
            encrypted_message = ""

            # move the position of each character in the message by the caesar key value
            for character in message:
                # get the ascii value for the character
                char_ascii = ord(character)

                # get the new character by adding the shift value to the old character
                encrypted_char = chr((char_ascii - 32 + self._caesar_key) % 95 + 32)
                encrypted_message += encrypted_char
            return encrypted_message

        except TypeError:
            return ""

    def _vigenere_square_encrypt(self, message) -> str:
        """ encryption using vigenere cipher"""
        try:
            message = str(message)
            enc_message = ""
            # set the value of the vigenere key value
            if self._create_keyword:
                random.seed(self._vigenere_key)

                for i in range(0, 256):
                    self.vigenere_keyword += str(chr(random.randint(65, 90)))

                self._create_keyword = False

            # get the length of the message received from the server
            string_length = len(message)

            # expand the encryption key making it longer the the message received
            expanded_key = self.vigenere_keyword
            expanded_key_length = len(expanded_key)

            # keep repeat the key until its size is greater than the message received size
            while expanded_key_length < string_length:
                expanded_key = expanded_key + self.vigenere_keyword  # repetition of the vigenere key
                expanded_key_length = len(expanded_key)

            key_position = 0

            for letter in message:
                if letter in self._alphabet:

                    # done for each letter in the message to find its numeric position in the alphabet
                    position = self._alphabet.find(letter)

                    # move along the key to find the character value
                    key_character = expanded_key[key_position]
                    key_character_position = self._alphabet.find(key_character)
                    key_position = key_position + 1

                    # find the position of the new character using the key
                    new_position = position + key_character_position + 1

                    # if the end of the alphabet is reached, the position continue from the beginning of the alphabet
                    if new_position > 90:
                        # NOTE: 91 is the total number of characters in the alphabet string
                        new_position = new_position - 91

                    # find the encrypted character from its position in the alphabet
                    new_character = self._alphabet[new_position]
                    enc_message = enc_message + new_character
                else:
                    enc_message = enc_message + letter
            return enc_message
        except TypeError:
            return ""

    def _caesar_cipher_decrypt(self, message) -> str:
        """decryption using caesar cypher

        the operation with the module % is used to keep the output value between 32 and 126, to get only
        valid ascii numbers
        note: the last ascii number (127) that represent the delete button is not included
        """
        try:
            message = str(message)
            encrypted_message = ""

            # set the value of the caesar key value

            # move the position of each character in the message by the caesar key value
            for character in message:
                # get the ascii value for the character
                char_ascii = ord(character)

                # get the new character by adding the shift value to the old character
                encrypted_char = chr((char_ascii - 32 - self._caesar_key) % 95 + 32)
                encrypted_message += encrypted_char
            return encrypted_message

        except TypeError:
            return ""

    def _vigenere_square_decrypt(self, message) -> str:
        """decryption using vigenere cipher"""
        try:
            message = str(message)
            dec_message = ""
            # set the value of the vigenere key value
            if self._create_keyword:
                random.seed(self._vigenere_key)

                for i in range(0, 256):
                    self.vigenere_keyword += str(chr(random.randint(65, 90)))

                self._create_keyword = False
                print("Keyword is: " + self.vigenere_keyword)
            # get the length of the message received from the server
            string_length = len(message)

            # expand the encryption key making it longer the the message received
            expanded_key = self.vigenere_keyword
            expanded_key_length = len(expanded_key)

            # keep repeat the key until its size is greater than the message received size
            while expanded_key_length < string_length:
                expanded_key = expanded_key + self.vigenere_keyword  # repetition of the vigenere key
                expanded_key_length = len(expanded_key)

            key_position = 0

            for letter in message:
                if letter in self._alphabet:

                    # done for each letter in the message to find its numeric position in the alphabet
                    position = self._alphabet.find(letter)

                    # move along the key to find the character value
                    key_character = expanded_key[key_position]
                    key_character_position = self._alphabet.find(key_character)
                    key_position = key_position + 1

                    # find the position of the original character using the key
                    new_position = position - key_character_position - 1

                    # if the end of the alphabet is reached, the position continue from the beginning of the alphabet
                    if new_position < 0:
                        # NOTE: 91 is the total number of characters in the alphabet string
                        new_position = new_position + 91

                    # find the decrypted character from its position in the alphabet
                    new_character = self._alphabet[new_position]
                    dec_message = dec_message + new_character
                else:
                    dec_message = dec_message + letter
            return dec_message
        except TypeError:
            return ""

    def generate_public_key(self):
        """calculate the public key for the server"""
        public_key = self._base ** self._private_key
        public_key = public_key % self._mod
        self._public_key = public_key
        return public_key

    def generate_shared_key(self, client_public_key):
        """calculate the shared key"""
        shared_key = int(client_public_key) ** self._private_key
        shared_key = shared_key % self._mod
        self._shared_key = shared_key
        return shared_key

    def _diffie_hellman_encrypt(self, message):
        """encryption using diffie hellman"""
        encrypted_message = ""
        key = self._shared_key
        for c in message:
            encrypted_message += chr(ord(c) + key)
        return encrypted_message

    def _diffie_hellman_decrypt(self, encrypted_message):
        """decryption using diffie hellman"""
        decrypted_message = ""
        key = self._shared_key

        # subtract the key for each character in the message
        for character in encrypted_message:
            decrypted_message += chr(ord(character) - key)
        return decrypted_message
