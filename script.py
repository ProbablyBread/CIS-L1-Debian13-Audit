#!/usr/bin/python3

import json
import subprocess
import os
import sys
import stat
import re
from datetime import timedelta
from datetime import datetime
from pathlib import Path

def IsExcludedGlobDir(path, excludedGlobDirs):
    # since this is using str.find()
    # if string is NOT found it's -1
    # returns true for strings that are found
    return any((str(path) + "/").find(g) > -1 for g in excludedGlobDirs)

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
            print(f"/etc/shadow: {shadowLine[0]} has last password change date in the future at {epochDate + timedelta(int(shadowLine[2]))}")

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

    rootPath = subprocess.run("sudo su - root -c \"printenv PATH\"", capture_output=True, shell=True)
    rootPath = rootPath.stdout.decode().strip()

    for path in rootPath.split(":"):
        if path == "":
            flag = True
            print(f"Empty path detected")
        elif path == ".":
            flag = True
            print(f"Current directory detected")
        else:
            p = Path(path)

            if not p.exists():
                flag = True
                print(f"Invalid directory {path} detected")
            else:
                st = p.stat()
                mode = st.st_mode

                if not st.st_uid == 0 or not st.st_gid == 0:
                    flag = True
                    print(f"Directory {path} is not owned by root")
                elif not stat.S_ISDIR(mode):
                    flag = True
                    print(f"Directory {path} is not a valid path")
                elif stat.S_IMODE(mode) > 0o755:
                    flag = True
                    print(f"Directory {path} is overly permissive (mode = {oct(mode).split('o')[1]})")

    if not flag:
        print("Audit passed for 5.4.2.5.\n")
    else:
        print("Audit failed for 5.4.2.5.\n")

def Check_7_1_11():
    print("Running audit for 7.1.11...")

    flag = False
    
    excludedTypes = ["nfs", "proc", "cifs", "smb", "vfat", "iso9660", "efivarfs", "selinuxfs", "ncpfs"]
    excludedRootDirs = {"/run", "/tmp", "/var/tmp", "/sys", "/snap", "/boot/efi", "/proc"}
    excludedGlobDirs = ["/containers/storage/", "/containerd/", "/kubelet/"]

    mounts = subprocess.run("findmnt --json -Dkeno fstype,target", shell=True, capture_output=True)
    mounts = json.loads(mounts.stdout.decode())

    # cache additional directories to ignore
    for mount in mounts["filesystems"]:
        if mount["fstype"] in excludedTypes:
            excludedRootDirs.add(mount["target"])

    top = Path("/")

    # loop through all files and directories under /
    for p in top.glob("**"):
        # if overall path doesn't start with excludedRootDirs
        dirCheck = not any(str(p).startswith(d) for d in excludedRootDirs)

        if p.is_dir() and dirCheck:
            # just check if directory is excluded
            if not IsExcludedGlobDir(p, excludedGlobDirs): 
                try: 
                    # follow symlinks, but flag broken ones
                    mode = p.stat().st_mode

                    # if is world writable without sticky bit set
                    if bool(mode & stat.S_IWOTH) and not bool(mode & stat.S_ISVTX):
                        flag = True
                        print(f"World writable dir without sticky bit: {p} ({oct(mode).split('o')[-1]})")
                except FileNotFoundError:
                    print(f"WARNING: Broken symlink at {p}")

        elif p.is_file() and dirCheck:
            # get parent directory and check if it's excluded
            if not IsExcludedGlobDir(p.parent, excludedGlobDirs):
                try: 
                    # follow symlinks, but flag broken ones
                    mode = p.stat().st_mode

                    # if is world writable
                    if bool(mode & stat.S_IWOTH):
                        flag = True
                        print(f"World writable file: {p} ({oct(mode).split('o')[-1]})")
                except FileNotFoundError:
                    print(f"WARNING: Broken symlink at {p}")

    if not flag:
        print("Audit passed for 7.1.11.\n")
    else:
        print("Audit failed for 7.1.11.\n")

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
    # print slowdown warning for any Python version < 3.13
    if sys.version_info.major <= 3 and sys.version_info.minor < 13:
        print("WARNING: Python versions <= 3.12.X will experience significant slow downs during the checks for 7.1.11 and 7.1.12.")
        print("You are encouraged to upgrade your Python version before using this script.")
        selection = ""

        while not re.match(r"[yYnN]", selection):
            selection = input("Acknowledge to continue (Y/N): ")

            if re.match(r"[Nn]", selection):
                print("Exiting.")
                exit(0)

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
