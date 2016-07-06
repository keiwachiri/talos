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
        if exists(dir_path):
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
        