import base64
import binascii
import hashlib
import sys
from typing import TextIO
import os
from datetime import datetime

import cryptography
from cryptography.fernet import Fernet


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


def base64_url_safe(string: str) -> str:
    string = string.encode("utf-8")
    return base64.urlsafe_b64encode(string)


def log_to_file(data):
    log_file = os.path.dirname(os.path.realpath(__file__)) + '\log'
    readerWrite = Reader(log_file, 'a+')
    readerWrite.file_content.write('Log time:' + str(datetime.now()) + '\n')
    readerWrite.file_content.write(data + '\n')
    del readerWrite


class ConsoleLogger(metaclass=Singleton):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def color(self, string: str, color_type) -> str:
        return color_type + string + self.ENDC


class Reader:
    def_files_mod: str = 'r'
    list_files_name: str = 'files.txt'
    file_name: str
    file_mode: str

    file_content: TextIO

    def __init__(self, file_name, file_mode=def_files_mod):
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
    additionalHash: str = 'op6sxM9WLEK0H7kTBpF5'
    crypt_key: str

    def __init__(self, date_for_crypt=''):
        if date_for_crypt == '':
            date_for_crypt = datetime.today().strftime('%Y%m%d%H%M')
        log_to_file(date_for_crypt)
        self.crypt_key = base64_url_safe(date_for_crypt + self.additionalHash)

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
            print("File %s are encryptet you fuckin rug!" % CL.color(file, CL.HEADER))
            return
        reader_wb = Reader(file, 'wb')
        reader_wb.write_file(decrypted_content)
        del reader_rb, reader_wb

    def encrypt_file(self, file: str):
        reader_rb = Reader(file, 'rb')
        encrypted_content = self.encrypt(reader_rb.get_whole_file())
        reader_wb = Reader(file, 'wb')
        reader_wb.write_file(encrypted_content)
        del reader_rb, reader_wb


def checkSysArgs():
    if not len(sys.argv) > 1:
        print("Add path to main scss file as argument!")
        exit()


# reader = Reader(Reader.list_files_name, 'r+')
# crypt = Crypt('202005132148')
# for line in reader.file_content:
#     crypt.decrypt_file(line)
# for line in reader.file_content:
#     crypt.encrypt_file(line)
CL = ConsoleLogger()
