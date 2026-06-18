#!/usr/bin/python3

import subprocess
from pathlib import Path
import os
import stat
import re
from datetime import timedelta
from datetime import datetime

def Check_5_2_5():
    print("Running audit for 5.2.5...")

    sudoersFiles = ["/etc/sudoers"]
    flag = False

    for filepath in Path("/etc/sudoers.d").glob("*"):
        sudoersFiles.append(filepath)

    for file in sudoersFiles:
        with open(file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            if re.match(r"(?i)^[^#].*!authenticate.*", line):
                flag = True
                print(f"{file}: {line.strip('\n')}")

    if not flag:
        print("Audit passed for 5.2.5.\n")
    else:
        print("Audit failed for 5.2.5.\n")

def Check_5_4_1_6():
    print("Running audit for 5.4.1.6...")

    epochDate = datetime(1970, 1, 1)
    currentDate = (datetime.now() - epochDate).days
    flag = False

    with open("/etc/shadow", 'r') as f:
        lines = f.readlines()

    for line in lines:
        shadowLine = line.split(":")
        changeDate = shadowLine[2]
        
        if int(changeDate) > currentDate:
            flag = True
            print(f"/etc/shadow: {shadowLine[0]} has last password change date at {epochDate + timedelta(int(shadowLine[2]))}")

    if not flag:
        print("Audit passed for 5.4.1.6.\n")
    else:
        print("Audit failed for 5.4.1.6.\n")

def Check_5_4_2_1():
    print("Running audit for 5.4.2.1...")

    flag = False

    with open("/etc/passwd", 'r') as f:
        lines = f.readlines()

    for line in lines:
        passwdLine = line.split(":")

        if passwdLine[0] != "root" and passwdLine[2] == "0":
            flag = True
            print(f"/etc/passwd: {passwdLine[0]} has UID 0")

    if not flag:
        print("Audit passed for 5.4.2.1.\n")
    else:
        print("Audit failed for 5.4.2.1.\n")

def Check_5_4_2_2():
    print("Running audit for 5.4.2.2...")

    flag = False

    with open("/etc/passwd", 'r') as f:
        lines = f.readlines()

    for line in lines:
        passwdLine = line.split(":")

        if passwdLine[0] != "root" and passwdLine[3] == "0":
            flag = True
            print(f"/etc/passwd: {passwdLine[0]} has GID 0")

    if not flag:
        print("Audit passed for 5.4.2.2.\n")
    else:
        print("Audit failed for 5.4.2.2.\n")

def Check_5_4_2_3():
    print("Running audit for 5.4.2.3...")

    flag = False

    with open("/etc/group", 'r') as f:
        lines = f.readlines()

    for line in lines:
        groupLine = line.split(":")

        if groupLine[0] != "root" and groupLine[2] == "0":
            flag = True
            print(f"/etc/group: {groupLine[0]} has GID 0")

    if not flag:
        print("Audit passed for 5.4.2.3.\n")
    else:
        print("Audit failed for 5.4.2.3.\n")

def Check_5_4_2_4():
    print("Running audit for 5.4.2.4...")

    flag = False

    with open("/etc/shadow", 'r') as f:
        lines = f.readlines()

    for line in lines:
        shadowLine = line.split(":")

        if shadowLine[0] == "root" and shadowLine[1] == "":
            flag = True
            print(f"/etc/shadow: root does not have a password")

    if not flag:
        print("Audit passed for 5.4.2.4.\n")
    else:
        print("Audit failed for 5.4.2.4.\n")

def Check_5_4_2_5():
    print("Running audit for 5.4.2.5...")

    flag = False

    # find a way to simulate root shell to PATH when logging in since sudo forces environment variables
    rootPath = subprocess.run("sudo su - root -c \"printenv PATH\"", capture_output=True, shell=True).stdout
    # this doesn't work
    exit(0)

    for path in rootPath.split(":"):
        if path == "":
            flag = True
            print(f"Empty path detected in {rootPath}")
        elif path == ".":
            flag = True
            print(f"Current directory \".\" detected in {rootPath}")
        else:
            p = Path(path)

            if not p.exists():
                flag = True
                print(f"Invalid directory {path} detected in {rootPath}")
            else:
                st = p.stat()
                mode = st.st_mode

                if not st.st_uid == 0 or not st.st_gid == 0:
                    flag = True
                    print(f"Directory {path} is not owned by root in {rootPath}")
                elif not stat.S_ISDIR(mode):
                    flag = True
                    print(f"Directory {path} is not a valid path in {rootPath}")
                elif stat.S_IMODE(mode) > 0o755:
                    flag = True
                    print(f"Directory {path} is overly permissive (mode = {oct(mode).split('o')[1]}) in {rootPath}")

    if not flag:
        print("Audit passed for 5.4.2.5.\n")
    else:
        print("Audit failed for 5.4.2.5.\n")

def Check_7_1_11():
    print("Running audit for 7.1.11...")

def Check_7_1_12():
    print("Running audit for 7.1.12...")

def Check_7_2_3():
    print("Running audit for 7.2.3...")

def Check_7_2_4():
    print("Running audit for 7.2.4...")

def Check_7_2_5():
    print("Running audit for 7.2.5...")

def Check_7_2_6():
    print("Running audit for 7.2.6...")

def Check_7_2_7():
    print("Running audit for 7.2.7...")

def Check_7_2_8():
    print("Running audit for 7.2.8...")

def Check_7_2_9():
    print("Running audit for 7.2.9...")

def Check_7_2_10():
    print("Running audit for 7.1.18...")

if __name__ == "__main__":
    if os.geteuid() == 0: 
        Check_5_2_5()
        Check_5_4_1_6()
        Check_5_4_2_1()
        Check_5_4_2_2()
        Check_5_4_2_3()
        Check_5_4_2_4()
        Check_5_4_2_5()
        Check_7_1_11()
        Check_7_1_12()
        Check_7_2_3()
        Check_7_2_4()
        Check_7_2_5()
        Check_7_2_6()
        Check_7_2_7()
        Check_7_2_8()
        Check_7_2_9()
        Check_7_2_10()
    else:
        print("Please run this script as root.")
