This file is for testing purpose only. It is not connected with the rest of the program
It contains the real password(in the program these password are salted and hashed) and 
usernames to test the program

login1@gmail.com          password1
login2@gmail.co.uk       password2
login3@unimail.co.uk     12345678
login4@hotmail.com       abcdefgh

The process to test is

LOGI -> username -> password -> HELO -> MAIL/IMSG
if MAIL then:
MAIL FROM:<email> -> RCPT TO:<email> -> RCPT OR DATA -> DATA -> MAIL/IMSG
if IMSG then:
IMSG TO:<username> ->imessage data entry -> MAIL/IMSG

You can turn on/off the timer from the SMTPServerlib.py changing the value of the variable
self._timeout to True to turn it on and False to turn it OFF

