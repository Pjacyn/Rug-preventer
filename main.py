import base64
import binascii
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
        try:
            self.file_content.close()
        except AttributeError:
            pass

    def write_file(self, data):
        self.file_content.write(data)

    def get_whole_file(self) -> str:
        return self.file_content.read()

    def get_next_line(self):
        return self.file_content.readline()


class Crypt:
    crypt_key: str

    def __init__(self, password=''):
        data = Crypt.random_string()
        IO.log_to_file(data)
        if password == '':
            self.crypt_key = Crypt.base64UrlSafe(data)
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
            HostBlocker.unblockHosts()
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

    @staticmethod
    def base64UrlSafe(url: str) -> str:
        url = url.encode("utf-8")
        return base64.urlsafe_b64encode(url)

    @staticmethod
    def random_string(string_length=32):
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(string_length))


class HostBlocker:
    win10_hosts = 'C:\Windows\System32\drivers\etc\hosts'
    starting_line = '\n#RugPreventer Start\n'
    ending_line = '\n#RugPreventer End'

    @staticmethod
    def blockHosts():
        HostBlocker.unblockHosts()
        writer = Reader(HostBlocker.win10_hosts, 'a+')
        readerUrls = Reader('urls.txt')
        writer.file_content.write(HostBlocker.starting_line)
        for line in readerUrls.file_content:
            writer.file_content.write(line)
        writer.file_content.write(HostBlocker.ending_line)
        del writer, readerUrls

    @staticmethod
    def unblockHosts():
        reader = Reader(HostBlocker.win10_hosts, 'r+')
        starting_line = HostBlocker.starting_line.strip('\n')
        ending_line = HostBlocker.ending_line.strip('\n')
        file = reader.file_content
        file_lines = file.readlines()
        file.seek(0)
        save_lines = True
        for line in file_lines:
            if save_lines:
                save_lines = line.find(starting_line) < 0
            if save_lines:
                file.write(line)
            else:
                if line.find(ending_line) >= 0:
                    save_lines = True
        file.truncate()
        del reader

    @staticmethod
    def checkAccess():
        try:
            Reader(HostBlocker.win10_hosts, 'w')
            return True
        except PermissionError:
            print('Access denied to file %s run program as admin' % HostBlocker.win10_hosts)
            return False


def myInputFunction():
    return raw_input()


class IO(metaclass=Singleton):
    pray_info = 'Pray to your king Pablo, you fucking rug!'
    exit_command = ['Pablo is my king', 'exit']
    ask_for_func_info = 'Your wish is my orders, you fucking rug!'
    start_info = \
        '1. Encrypt your fucking rug files and block urls\n' \
        '2. Decrypt your fucking jug files and block urls\n' \
        'To exit just write: "' + exit_command[0] + '"'
    password_info = 'Your password is: %s YOU RUG!'
    password_ask_info = 'Gimme your fucking rugy password'
    warranty_info = 'The program does not contain any warranty!!!\n' \
                    'You use it on your own responsibility.\n' \
                    'Program only for fucking RUGS AND JUGS!\n\n'

    files_needed = {
        'files.txt': 'In file: %s you should put all path to files with you want to block',
        'urls.txt': 'In file: %s you should put all urls with you want to block'
    }
    absolute_path = os.path.dirname(os.path.realpath(__file__))

    def run(self):
        if not HostBlocker.checkAccess():
            return
        raw_in = ''
        print(CL.color(IO.warranty_info, CL.FAIL))
        time.sleep(3)
        IO.check_files()
        raw_in = ''
        while raw_in not in self.exit_command:
            print(self.start_info)
            raw_in = myInputFunction()
            self.loadFunction(raw_in)

    @staticmethod
    def encrypt():
        reader = Reader()
        crypt = Crypt()
        HostBlocker.blockHosts()
        for file in reader.file_content:
            print(file)
            crypt.encrypt_file(file)
        print(IO.password_info % CL.color(crypt.getPassword(), CL.WARNING))

    @staticmethod
    def decrypt():
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
            IO.allFunctions[name]()
        else:
            print('You are fuckin dumb rug mate :(')

    allFunctions = {
        "1": encrypt.__func__,
        "2": decrypt.__func__,
    }

    @staticmethod
    def check_files():
        for file in IO.files_needed:
            file_path = IO.absolute_path + '\\' + file
            if not os.path.exists(file_path):
                Reader(file, 'a+')
                print(IO.files_needed[file] % file_path)

    @staticmethod
    def log_to_file(data):
        log_file = IO.absolute_path + '\log'
        readerWrite = Reader(log_file, 'a+')
        readerWrite.file_content.write('Log time:' + str(datetime.now()) + '\n')
        readerWrite.file_content.write(data + '\n')
        del readerWrite


CL = ConsoleLogger()
io = IO()
io.run()
