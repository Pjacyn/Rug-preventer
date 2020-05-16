import base64
import binascii
import hashlib
import string
import random
from typing import TextIO
import os
from datetime import datetime
import time

import cryptography
from cryptography.fernet import Fernet
from pip._vendor.distlib.compat import raw_input


class WrongPassword(Exception):
    message = 'Wrong password rug mate'
    pass


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


def create_files():
    line = reader.get_next_line()
    readerWrite = Reader(Reader.list_files_name, 'w')
    readerWrite.file_content.write(line + '\n')
    path = os.path.dirname(line)
    m = hashlib.md5()
    for i in range(0, 20):
        fileName = hashlib.md5((str(datetime.now()) + str(i)).encode('utf-8')).hexdigest()
        full_path = path + '\\' + fileName
        print(path)
        print(full_path)
        if not os.path.exists(full_path):
            with open(full_path, 'w'): pass
            readerWrite.file_content.write(full_path + '\n')


def log_to_file(data):
    log_file = os.path.dirname(os.path.realpath(__file__)) + '\log'
    readerWrite = Reader(log_file, 'a+')
    readerWrite.file_content.write('Log time:' + str(datetime.now()) + '\n')
    readerWrite.file_content.write(data + '\n')
    del readerWrite


def random_string(stringLength=32):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(stringLength))


class ConsoleLogger(metaclass=Singleton):
    # HEADER = '\033[95m'
    # OKBLUE = '\033[94m'
    # OKGREEN = '\033[92m'
    # WARNING = '\033[93m'
    # FAIL = '\033[91m'
    # ENDC = '\033[0m'
    # BOLD = '\033[1m'
    # UNDERLINE = '\033[4m'
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    BOLD = ''
    UNDERLINE = ''

    def color(self, string: str, color_type) -> str:
        return color_type + string + self.ENDC


class Reader:
    def_files_mod: str = 'r'
    list_files_name: str = 'files.txt'
    file_name: str
    file_mode: str
    file_content: TextIO

    def __init__(self, file_name=list_files_name, file_mode=def_files_mod):
        self.file_name = file_name.rstrip()
        self.file_mode = file_mode
        try:
            self.file_content = open(self.file_name, self.file_mode)
        except FileNotFoundError:
            print('File no founded you fucking rug. This fucking file: ' + self.file_name)

    def __del__(self):
        self.file_content.close()

    def write_file(self, data):
        self.file_content.write(data)

    def get_whole_file(self) -> str:
        return self.file_content.read()

    def get_next_line(self):
        return self.file_content.readline()


class Crypt:
    crypt_key: str

    def __init__(self, password=''):
        data = random_string()
        log_to_file(data)
        if password == '':
            self.crypt_key = self.base64UrlSafe(data)
        else:
            self.crypt_key = password

    def encrypt(self, file: str):
        return Fernet(self.crypt_key).encrypt(file)

    def decrypt(self, file: str):
        return Fernet(self.crypt_key).decrypt(file)

    def decrypt_file(self, file: str):
        file = file.rstrip()
        reader_rb = Reader(file, 'rb')
        try:
            decrypted_content = self.decrypt(reader_rb.get_whole_file())
        except cryptography.fernet.InvalidToken:
            print("File %s %s you fuckin rug!" % (
                CL.color(file, CL.HEADER), CL.color('can\'t be decryptet', CL.FAIL)))
            return
        except binascii.Error:
            raise WrongPassword()
        reader_wb = Reader(file, 'wb')
        reader_wb.write_file(decrypted_content)
        print("File %s %s you fuckin rug!" % (CL.color(file, CL.HEADER), CL.color('was decryptet', CL.OKGREEN)))
        del reader_rb, reader_wb

    def encrypt_file(self, file: str):
        reader_rb = Reader(file, 'rb')
        encrypted_content = self.encrypt(reader_rb.get_whole_file())
        reader_wb = Reader(file, 'wb')
        reader_wb.write_file(encrypted_content)
        print("File %s %s you fuckin rug!" % (CL.color(file, CL.HEADER), CL.color('was encrypted', CL.OKGREEN)))
        del reader_rb, reader_wb

    def getPassword(self):
        result = self.crypt_key.decode('utf-8')
        return result

    def base64UrlSafe(self, string: str) -> str:
        string = string.encode("utf-8")
        return base64.urlsafe_b64encode(string)


def myInputFunction():
    return raw_input()


class IO(metaclass=Singleton):
    pray_info = 'Pray your king Pablo, you fucking rug!'
    exit_command = ['Pablo is my king', 'exit']
    ask_for_func_info = 'Your wish is my orders, you fucking rug!'
    start_info = \
        '1. Encrypt your fucking rug files\n' \
        '2. Decrypt your fucking jug files\n' \
        'To exit just write: "' + exit_command[0] + '"'
    password_info = 'Your password is: %s YOU RUG!'
    password_ask_info = 'Gimme your fucking rugy password'
    warranty_info = 'The program does not contain any warranty!!!\n' \
                    'You use it on your own responsibility.\n' \
                    'Program only for fucking RUGS AND JUGS!\n\n'

    def run(self):
        raw_in = ''
        print(CL.color(IO.warranty_info, CL.FAIL))
        time.sleep(3)
        raw_in = ''
        while raw_in not in self.exit_command:
            print(self.start_info)
            raw_in = myInputFunction()
            self.loadFunction(raw_in)

    def encrypt(self):
        reader = Reader()
        crypt = Crypt()
        for file in reader.file_content:
            print(file)
            crypt.encrypt_file(file)
        print(IO.password_info % CL.color(crypt.getPassword(), CL.WARNING))

    def decrypt(self):
        print(IO.password_ask_info)
        raw_in = myInputFunction()
        reader = Reader()
        crypt = Crypt(raw_in)
        for file in reader.file_content:
            try:
                crypt.decrypt_file(file)
            except WrongPassword:
                print(CL.color(WrongPassword.message, CL.WARNING))
                break

    def loadFunction(self, name, args=''):
        if name in self.allFunctions:
            self.allFunctions[name](args)
        else:
            print('You are fuckin dumb rug mate :(')

    allFunctions = {
        "1": encrypt,
        "2": decrypt,
    }


CL = ConsoleLogger()

io = IO()
io.run()
