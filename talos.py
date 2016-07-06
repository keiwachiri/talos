#/usr/bin/python3
"""
    DESCRIPTION:
        Talos is a script whose purpose is to collect, compress and optionally
        encrypt an arbitrary number of files and directories

    USAGE:
        `./talos.py -d [directories] -f [files] -o output_file`
        'python talos.py -d [directories] -f [files] -o output_file'

    ARGUMENTS:
        -d argument represents the directories (one or more) that we want
            collected. Paths can be relative or absolute
        -f argument represents the files that we want collected. Paths can
            be relative or absolute
        - o argument represents the output file that contains the final
            processed data
        - m argument represents the desired compression method:
            `stored` for storing uncompressed data
            `deflated` for the standard ZIP compression method
            `bzip2` for the BZIP2 compression method
            `lzma` for the LZMA compression method
            Defaults to `deflated` - standard ZIP compression method
        --skip-hidden is a flag used in case user wants to skip hidden
            files/directories in the directories provided as arguments.
            Defaults to False
        -- encrypt flag used in case user wants the output file to be safely
            encrypted. In this case user will be prompted for a password that
            will be used to create the key required for successful encryption

    BASIC CONCEPT:
        - allows arbitrary number of directories and files
        - paths can be given as relative or absolute
        - in the output file full paths are not recreated, directories are
            added by their basename
        - allows ommitting hidden files
        - allows encryption of the output file via the password that user is
            prompted for. Uses AES256 for encryption
"""

import os
import sys
from datetime import datetime
import zipfile
import argparse
import hashlib
import getpass

from Crypto.Cipher import AES
from Crypto import Random


# TODO - add option to plug disfigure password function as an argument
# TODO - optimize memory USAGE
# TODO - add upload option somehow


python_v = sys.version_info.major


if python_v == 3:
    compression_methods = {
        "deflated": zipfile.ZIP_DEFLATED,
        "stored": zipfile.ZIP_STORED,
        "bzip2": zipfile.ZIP_BZIP2,
        "lzma": zipfile.ZIP_LZMA,
    }
elif python_v == 2:
    # Necessary because Python 2 does not support bzip and lzma methods
    compression_methods = {
        "deflated": zipfile.ZIP_DEFLATED,
        "stored": zipfile.ZIP_STORED,
    }


class AESCipher:
    def __init__(self, key, vecto):
        self.key = key
        if not len(vector) == 16:
            raise ValueError("Vector must be of length 16")
        self.vector = vector
        self.encrypt_cipher = AES.new(self.key, AES.MODE_CBC, self.vector)
        self.decrypt_cipher = AES.new(self.key, AES.MODE_CBC, self.vector)

    def encrypt(self, raw):
        raw = pad(raw)
        ciphertext = self.encrypt_cipher.encrypt(raw)
        return ciphertext

    def decrypt(self, enc):
        plaintext = self.decrypt_cipher.decrypt(enc)
        return plaintext



def write_directory(abs_path, zip_file, skip_hidden=False):
    path, name = os.path.split(abs_path)
    for root, dirs, files in os.walk(abs_path):
        if skip_hidden:
            files = [f for f in files if not f[0] == '.']
            # tricky - has to change the actual objects
            dirs[:] = [d for d in dirs if not d[0] == '.']
        for f in files:
            print("Writing file: %s in directory %s" % (f, root))
            zip_file.write(os.path.join(root, f),
                           arcname=os.path.join(root[len(path)+1:], f))
            print("Finished writing file: %s in directory: %s" % (f, root))


def write_file(abs_path, zip_file):
    print("Writing file: %s" % abs_path)
    zip_file.write(abs_path, arcnam=os.path.basename(abs_path))
    print("Finished writing file: %s" % abs_path)


def zip_it(dirs, files, output_file, method, skip_hidden=False, encrypt=False):
    if not method in compression_methods:
        print("No such method %s supported" % method)
        sys.exit(1)
    if encrypt:
        print("Not supported yet!")
        sys.exit(1)
    start = datetime.now()
    comp_method = compression_methods[method]
    dirs_to_zip = []
    files_to_zip = []
    for d in dirs:
        dir_path = os.path.normpath(os.path.join(os.getcwd(), d))
        if os.path.exists(dir_path):
            dirs_to_zip.append(dir_path)
        else:
            print("Invalid directory given: %s" % d)
    for f in files:
        file_path = os.path.normpath(os.path.join(os.getcwd(), f))
        if os.path.exists(file_path):
            files_to_zip.append(file_path)
        else:
            print("Invalid file given: %s" % f)
    with zipfile.ZipFile(output_file, "w", comp_method,
                         allowZip64=True) as zip_file:
        for d in dirs_to_zip:
            write_directory(d, zip_file, skip_hidden=skip_hidden)
        for f in files_to_zip:
            write_file(f, zip_file)
    end = datetime.now()
    time_diff = end - start
    print("DONE")
    print("Time Elapsed: %s" % time_diff)


def size_of_fmt(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(size) < 1024.0:
            return "%3.2f%s" % (size, unit)
        size /= 1024.0
    return "%.1f%s" % (num, "TB")


def get_password():
    password = getpass.getpass()
    while len(password) < 10:
        password = getpass.getpass("Password must be 10 char long atleast! ")
    password_repeat = ''
    while password_repeat != password:
        password_repeat = getpass.getpass("Confirm your passwornd: ")
    return password


def disfigure_password(password):
    disfigured_password = ""
    for ind in range(len(password)):
        disfigured_password += ("%d%s%d%s%d%s" %
            (ind, chr(ord('a') + ind), ord('a') + ind, password[ind],
             ord('a') - ind, chr(ord(password[ind]) +
                                 len(password) - ind).capitalize()))
    return disfigured_password


def create_key(password):
    disfigured_password = disfigure_password(password)
    key_hash_obj = hashlib.sha256(password.encode())
    return key_hash_obj.digest()


def pad(block):
    size = 16
    if not len(block) == 16:
        block = block + ((size - len(block) % size) *
                         chr(size - (len(block) % size)).encode())
    return block


def unpad(block):
    return block[:-ord(block[-1])]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect arbitrary list of "
                                     "files and directories into single file")
    parser.add_argument("-d", type=str, nargs="+", default=[],
                        help="directories that will be processed")
    parser.add_argument("-f", type=str, nargs="+", default=[],
                        help="files that will be processed")
    parser.add_argument("-o", type=str, help="desired name of output file",
                        default="talos.zip")
    parser.add_argument("-m", type=str, help="compression mode",
                        default="deflated", choices=compression_methods)
    parser.add_argument("--skip-hidden", help="skip hidden files and dirs",
                        action="store_const", const=True, default=False)
    args = parser.parse_args()
    zip_it(args.d, args.f, args.o, args.m, skip_hidden=args.skip_hidden)
