import hashlib
from typing import TextIO
import os
import datetime
from cryptography.fernet import Fernet


def create_files():
    line = reader.get_next_line()
    readerWrite = Reader(Reader.list_files_name, 'w')
    readerWrite.file_content.write(line + '\n')
    path = os.path.dirname(line)
    m = hashlib.md5()
    for i in range(0, 20):
        fileName = hashlib.md5((str(datetime.datetime.now()) + str(i)).encode('utf-8')).hexdigest()
        full_path = path + '\\' + fileName
        print(path)
        print(full_path)
        if not os.path.exists(full_path):
            with open(full_path, 'w'): pass
            readerWrite.file_content.write(full_path + '\n')


def log_to_file(data):
    log_file = os.path.dirname(os.path.realpath(__file__)) + '\log'
    readerWrite = Reader(log_file, 'a+')
    readerWrite.file_content.write('Log time:' + str(datetime.datetime.now()) + '\n')
    readerWrite.file_content.write(data + '\n')
    del readerWrite


class Reader:
    def_files_mod: str = 'r'
    list_files_name: str = 'files.txt'
    file_name: str
    file_mode: str
    file_content: TextIO

    def __init__(self, file_name, file_mode=def_files_mod):
        self.file_name = file_name.rstrip()
        self.file_mode = file_mode
        print(self.file_name)
        try:
            self.file_content = open(self.file_name, self.file_mode)
        except FileNotFoundError:
            print('File no founded you fucking rug. This fucking file: ' + self.file_name)

    def __del__(self):
        self.file_content.close()

    def write_file(self, data):
        self.file_content.write(data)

    def get_whole_file(self):
        return self.file_content.read()

    def get_next_line(self):
        return self.file_content.readline()


class Crypt:
    additionalHash: str = 'Zcby^BuwFJcwSJ97Ky%ej@9RU3'
    crypt_key: str

    def __init__(self, date_for_crypt=''):
        now = datetime.datetime.now()
        if date_for_crypt == '':
            date_for_crypt = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute)
        log_to_file(date_for_crypt)
        encode_hash = hashlib.md5(date_for_crypt.encode()).hexdigest()
        self.crypt_key = encode_hash + self.additionalHash

    def encrypt(self, file: str):
        return Fernet(self.crypt_key).encrypt(file)

    def decrypt(self, file: str):
        return Fernet(self.crypt_key).decrypt(file)

    def decrypt_file(self, file: str):
        reader_rb = Reader(file, 'rb')
        decrypted_content = self.decrypt(reader_rb.get_whole_file())
        reader_wb = Reader(file, 'wb')
        reader_wb.write_file(decrypted_content)
        del reader_rb, reader_wb

    def encrypt_file(self, file: str):
        reader_rb = Reader(file, 'rb')
        encrypted_content = self.encrypt(reader_rb.get_whole_file())
        reader_wb = Reader(file, 'wb')
        reader_wb.write_file(encrypted_content)
        del reader_rb, reader_wb


reader = Reader(Reader.list_files_name, 'r+')
crypt = Crypt('2020513025')

for line in reader.file_content:
    crypt.encrypt_file(line)
