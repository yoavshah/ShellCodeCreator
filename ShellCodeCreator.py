from subprocess import Popen, PIPE
import re
import os
import pefile
import argparse
import logging as log
from pathlib import Path

COMPILE_COMMAND = "cl /c /FA /GS- {}\n"
LINK_COMMANDS = "ml /c {} && link {} /entry:main\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--srcfile", dest="srcfile", help="C Source file.", required=True, type=str)
    parser.add_argument("-p", "--vsdev_path", dest="vsdev_path", help="Full path for VsDevCmd.bat.", required=True, type=str)
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO)
        log.info("Verbose output.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")

    src_filename = str(Path(args.srcfile).name)
    filename = str(Path(args.srcfile).stem)
    output_path = str(Path(args.srcfile).resolve().parent)

    log.info("Opening VsDevTools Shell.")
    p = Popen(["cmd", "/k", args.vsdev_path], cwd=output_path, stdin=PIPE, stdout=PIPE)

    log.info("Running compilation command.")
    output = p.communicate(COMPILE_COMMAND.format(src_filename).encode())[0].decode()
    log.info("Output: " + output)

    log.info("Opening asm file to remove includes and other no needed code lines.")
    f = open(os.path.join(output_path, filename) + ".asm", "r")
    new_file_content = re.sub("(INCLUDELIB.*)|(include.*)", ";", f.read())
    f.close()

    index = new_file_content.find("PUBLIC")
    new_file_content = new_file_content[:index] + "\nassume fs:nothing\n" + new_file_content[index:]

    log.info("Writing the new assembly file.")
    f = open(os.path.join(output_path, filename) + ".asm", "w")
    f.write(new_file_content)
    f.close()

    log.info("Opening VsDevTools Shell Again.")
    p = Popen(["cmd", "/k", args.vsdev_path], cwd=output_path, stdin=PIPE, stdout=PIPE)

    log.info("Running linking command.")
    output = p.communicate(LINK_COMMANDS.format(filename + ".asm", filename + ".obj").encode())[0].decode()
    log.info("Output: " + output)

    log.info("Dumping the .text section.")
    f = open(os.path.join(output_path, filename) + ".text", "wb")
    pe = pefile.PE(os.path.join(output_path, filename) + ".exe")
    for section in pe.sections:
        if section.Name.startswith(b".text"):
            f.write(section.get_data())
            break
    f.close()

    log.info("Creating a shellcode char array in C language.")
    START = "char shell_code[] = {"
    output = START
    f = open(os.path.join(output_path, filename) + ".text", "rb")
    c = 0
    data = f.read()
    data = data.rstrip(b"\x00")
    for i, b in enumerate(data):
        output += "0x{:02x}".format(b)
        if i == len(data) - 1:
            break
        if c == 10:
            c = 0
            output += ",\n{}".format(" "*len(START))
        else:
            c += 1
            output += ", "

    f.close()


    f = open(os.path.join(output_path, filename) + ".text" + ".c", "w")
    output = output + "};"
    f.write(output)
    f.close()
    log.info("Finished writing the shellcode.")
    log.info("Checkout {}.".format(os.path.join(output_path, filename) + ".text" + ".c"))











