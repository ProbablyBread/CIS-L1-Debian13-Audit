#!/usr/bin/env python3

from functions import Helpers

import json
import subprocess
import os
import sys
import stat
import re
import pwd
import grp
import hashlib
from datetime import timedelta
from datetime import datetime
from pathlib import Path

def RunCheck(argument):
    match argument:
        case "1.2.1.1": Check_1_2_1_1()
        case "5.2.5": Check_5_2_5()
        case "5.4.1.6": Check_5_4_1_6()
        case "5.4.2.1": Check_5_4_2_1()
        case "5.4.2.2": Check_5_4_2_2()
        case "5.4.2.3": Check_5_4_2_3()
        case "5.4.2.4": Check_5_4_2_4()
        case "5.4.2.5": Check_5_4_2_5()
        case "7.1.11": Check_7_1_11()
        case "7.1.12": Check_7_1_12()
        case "7.1.13": Check_7_1_13()
        case "7.2.3": Check_7_2_3()
        case "7.2.4": Check_7_2_4()
        case "7.2.5": Check_7_2_5()
        case "7.2.6": Check_7_2_6()
        case "7.2.7": Check_7_2_7()
        case "7.2.8": Check_7_2_8()
        case "7.2.9": Check_7_2_9()
        case "7.2.10": Check_7_2_10()
        case "All" | "all": RunAll()
        case _: print("Invalid audit.\n")

def RunAll():
    Check_1_2_1_1()
    Check_5_2_5()
    Check_5_4_1_6()
    Check_5_4_2_1()
    Check_5_4_2_2()
    Check_5_4_2_3()
    Check_5_4_2_4()
    Check_5_4_2_5()
    Check_7_1_11()
    Check_7_1_12()
    Check_7_1_13()
    Check_7_2_3()
    Check_7_2_4()
    Check_7_2_5()
    Check_7_2_6()
    Check_7_2_7()
    Check_7_2_8()
    Check_7_2_9()
    Check_7_2_10()

def Check_1_2_1_1():
    print("Running audit for 1.2.1.1...")

    auditFlag = False
    signedByFlag = False

    p = Path("/etc/apt")

    for file in p.glob("**"):
        # handle .list files
        if str(file).endswith(".list"):
            with open(file) as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                if not re.match(r"(?i)^[^#\r\n].*signed-by.*$", line):
                    auditFlag = True
                    print(f"Missing Signed-By at line {i + 1} in {file}")

        # handle .sources files (deb822)
        if str(file).endswith(".sources"):
            stanzas = Helpers.ParseDeb822(file)

            # loop through each stanza
            for i in stanzas:
                # reset flag
                signedByFlag = False

                # loop through each line in the stanza
                for line in stanzas.get(i):
                    # check if signed-by exists
                    if re.match(r"(?i)^signed-by.*$", line):
                        signedByFlag = True
                        
                        # check if signed-by has a pgp key
                        if line.split(":")[1].strip() == "":
                            auditFlag = True
                            print(f"Empty Signed-By for stanza {i + 1} in {file}")

                # if signed-by is missing
                if not signedByFlag:
                    auditFlag = True
                    print(f"Missing Signed-By for stanza {i + 1} in {file}")

    if not auditFlag:
        print("Audit passed for 1.2.1.1.\n")
    else:
        print("Audit failed for 1.2.1.1.\n")

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
                    print(f"Directory {path} is overly permissive (mode = {oct(mode).split('o')[-1]})")

    if not flag:
        print("Audit passed for 5.4.2.5.\n")
    else:
        print("Audit failed for 5.4.2.5.\n")

def Check_7_1_11():
    print("Running audit for 7.1.11...")

    flag = False

    excludedRootDirs, excludedGlobDirs = Helpers.GetDirExclusions()
    
    # loop through all files and directories under /
    for path, dirnames, filenames in os.walk("/", topdown=True):
        # match any excluded root directory in excludedRootDirs
        # match any excluded glob directory in excludedGlobDirs
        # clear dirnames if either match and go to next loop
        if any(path.startswith(d) for d in excludedRootDirs) or any((str(path) + "/").find(g) > -1 for g in excludedGlobDirs):
            dirnames.clear()
            continue

        # handle directory
        try:
            mode = os.stat(path).st_mode

            # check if directory is world writable and whether the sticky bit is set
            if bool(mode & stat.S_IWOTH) and not bool(mode & stat.S_ISVTX):
                flag = True
                print(f"World writable dir without sticky bit: {path} ({oct(mode).split('o')[-1]})")
        except FileNotFoundError:
            print(f"WARNING: Broken symlink at {path}")

        # handle files
        for file in filenames:
            try:
                filepath = os.path.join(path, file)
                mode = os.stat(filepath).st_mode

                # check if file is world writable and whether it's actually a file
                if bool(mode & stat.S_IWOTH) and stat.S_ISREG(mode):
                    flag = True
                    print(f"World writable file: {filepath} ({oct(mode).split('o')[-1]})")
            except FileNotFoundError:
                print(f"WARNING: Broken symlink at {filepath}")

    if not flag:
        print("Audit passed for 7.1.11.\n")
    else:
        print("Audit failed for 7.1.11.\n")

def Check_7_1_12():
    print("Running audit for 7.1.12...")

    flag = False

    excludedRootDirs, excludedGlobDirs = Helpers.GetDirExclusions()

    # loop through all files and directories under /
    for path, dirnames, filenames in os.walk("/", topdown=True):
        # match any excluded root directory in excludedRootDirs
        # match any excluded glob directory in excludedGlobDirs
        # clear dirnames if either match and go to next loop
        if any(path.startswith(d) for d in excludedRootDirs) or any((str(path) + "/").find(g) > -1 for g in excludedGlobDirs):
            dirnames.clear()
            continue

        # handle directory
        try:
            # follow symlink
            mode = os.stat(path)
        except FileNotFoundError:
            print(f"WARNING: Broken symlink at {path}")
            mode = os.lstat(path)

        try: 
            uid = pwd.getpwuid(mode.st_uid)
            gid = grp.getgrgid(mode.st_gid)
        except KeyError:
            flag = True
            print(f"Unowned directory: {path} with UID={mode.st_uid},GID={mode.st_gid}")

        # handle files
        for file in filenames:
            try: 
                filepath = os.path.join(path, file)
                mode = os.stat(filepath)
            except FileNotFoundError:
                print(f"WARNING: Broken symlink at {filepath}")
                mode = os.lstat(filepath)

            try:
                uid = pwd.getpwuid(mode.st_uid)
                gid = grp.getgrgid(mode.st_gid)
            except KeyError:
                flag = True
                print(f"Unowned file: {filepath} with UID={mode.st_uid},GID={mode.st_gid}")

    if not flag:
        print("Audit passed for 7.1.12.\n")
    else:
        print("Audit failed for 7.1.12.\n")

def Check_7_1_13():
    print("Running audit for 7.1.13...")

    stickyBitList = []
    excludedRootDirs = Helpers.GetDirExclusionsWithOptions()

    flag = False

    # walk everything from /
    for path, dirnames, filenames in os.walk("/", topdown=True):
        # except excluded dirs
        if any(path.startswith(d) for d in excludedRootDirs):
            dirnames.clear()
            continue

        # get files with SUID and SGID bits
        for file in filenames:
            filepath = os.path.join(path, file)
            mode = os.lstat(filepath).st_mode # don't follow symlinks

            # stickyBitList[i][0] - SUID or SGID
            # stickyBitList[i][1] - full file path
            if bool(mode & stat.S_ISUID):
                stickyBitList.append(["SUID", filepath])
            if bool(mode & stat.S_ISGID):
                stickyBitList.append(["SGID", filepath])

    # loop through all files
    for file in stickyBitList:
        # get package from dpkg -S
        dpkgSource = subprocess.run(f"dpkg -S {file[1]}", shell=True, capture_output=True)

        # calculate md5sum for file
        with open(file[1], 'rb') as f:
            digest = hashlib.file_digest(f, "md5").hexdigest()
       
        # if file is part of a package installed with dpkg/apt
        if dpkgSource.returncode == 0:
            dpkgSource = dpkgSource.stdout.decode().split(":")[0]

            # check against /var/lib/dpkg/info/<dpkgSource>.md5sums
            with open(f"/var/lib/dpkg/info/{dpkgSource}.md5sums", 'r') as f:
                sums = f.read()

            # md5sum format matches <digest>  path/to/binary 
            # first / needs to be sliced off while matching
            if not re.findall(rf"{digest}\s+{file[1][1:]}", sums):
                flag = True
                print(f"md5sum does not match for {file[0]} file - {digest}: {file[1]}")
        # otherwise, assume malicious
        else:
            flag = True
            print(f"Unknown {file[0]} file - {digest}: {file[1]}")

    if not flag:
        print("Audit passed for 7.1.13.\n")
    else:
        print("Audit failed for 7.1.13.\n")

def Check_7_2_3():
    print("Running audit for 7.2.3...")

    flag = False

    # grab all assigned groups in /etc/passwd
    with open("/etc/passwd", 'r') as f:
        passwd = f.readlines()

    for line in passwd:
        # use grp library to match GID
        username = line.split(":")[0]
        gid = line.split(":")[3]

        # if GID returns no match, flag = True
        try:
            grp.getgrgid(int(gid))
        except KeyError:
            flag = True
            print(f"{username} belongs in GID {gid} which is not a valid group.")

    if not flag:
        print("Audit passed for 7.2.3.\n")
    else:
        print("Audit failed for 7.2.3.\n")

def Check_7_2_4():
    print("Running audit for 7.2.4...")

    flag = False

    # grab the shadow group in /etc/shadow
    with open("/etc/group", 'r') as f:
        groups = f.readlines()

    for g in groups:
        if g.startswith("shadow:") and not re.match(r"^shadow:x:\d+:$", g):
            flag = True
            print(f"The shadow group is not empty, containing the user(s) {g.split(':')[-1]}")

    if not flag:
        print("Audit passed for 7.2.4.\n")
    else:
        print("Audit failed for 7.2.4.\n")

def Check_7_2_5():
    print("Running audit for 7.2.5...")

    flag = False
    uids = {}

    # read the entire passwd file, grab UIDs into an array
    with open("/etc/passwd", 'r') as f:
        passwd = f.readlines()

    for line in passwd:
        username = line.split(":")[0]
        uid = line.split(":")[2]

        if not uid in uids:
            uids[uid] = [username]
        else:
            uids[uid].append(username)

    for uid in uids:
        if len(uids[uid]) > 1:
            flag = True
            print(f"Duplicate UID {uid} between {Helpers.ArrayToText(uids[uid])}")

    if not flag:
        print("Audit passed for 7.2.5.\n")
    else:
        print("Audit failed for 7.2.5.\n")

def Check_7_2_6():
    print("Running audit for 7.2.6...")

    flag = False
    gids = {}

    # read the entire group file, grab GIDs into an array
    with open("/etc/group", 'r') as f:
        group = f.readlines()

    for line in group:
        groupname = line.split(":")[0]
        gid = line.split(":")[2]

        if not gid in gids:
            gids[gid] = [groupname]
        else:
            gids[gid].append(groupname)

    for gid in gids:
        if len(gids[gid]) > 1:
            flag = True
            print(f"Duplicate GID {gid} between {Helpers.ArrayToText(gids[gid])}")

    if not flag:
        print("Audit passed for 7.2.6.\n")
    else:
        print("Audit failed for 7.2.6.\n")

def Check_7_2_7():
    print("Running audit for 7.2.7...")

    flag = False
    usernames = []

    with open("/etc/passwd", 'r') as f:
        passwd = f.readlines()

    for line in passwd:
        usernames.append(line.split(":")[0])

    for u in usernames:
        if usernames.count(u) > 1:
            flag = True
            print(f"Duplicate username {u}")
            # remove from array to avoid duplicating messages
            usernames = [a for a in usernames if a != u]

    if not flag:
        print("Audit passed for 7.2.7.\n")
    else:
        print("Audit failed for 7.2.7.\n")

def Check_7_2_8():
    print("Running audit for 7.2.8...")

    flag = False
    groupnames = []

    with open("/etc/group", 'r') as f:
        group = f.readlines()

    for line in group:
        groupnames.append(line.split(":")[0])

    for g in groupnames:
        if groupnames.count(g) > 1:
            flag = True
            print(f"Duplicate groupname {g}")
            # remove from array to avoid duplicating messages
            groupnames = [a for a in groupnames if a != g]

    if not flag:
        print("Audit passed for 7.2.8.\n")
    else:
        print("Audit failed for 7.2.8.\n")

def Check_7_2_9():
    print("Running audit for 7.2.9...")

    flag = False
    homeDirs = {}

    with open("/etc/passwd", 'r') as f:
        passwd = f.readlines()

    with open("/etc/shells", 'r') as f:
        shells = [s.strip() for s in f.readlines() if not s.startswith("#")]

    for line in passwd:
        user = line.split(":")[0].strip()
        shell = line.split(":")[-1].strip()
        homeDir = line.split(":")[5].strip()

        if shell in shells:
            homeDirs[user] = homeDir

    for user in homeDirs:
        path = homeDirs[user]

        # checks if path exists or is an actual directory
        if not os.path.exists(path):
            flag = True
            print(f"Interactive user {user} has an invalid home directory of {homeDirs[user]}")
        else:
            mode = os.stat(path)

            # check if path is a directory
            if not stat.S_ISDIR(mode.st_mode): 
                flag = True
                print(f"Interactive user {user} has an invalid home directory of {homeDirs[user]}")

            # checks if path has permissions <= 750
            elif bool(mode.st_mode & stat.S_IRWXO) or bool(mode.st_mode & stat.S_IWGRP) or not bool(mode.st_mode & stat.S_IRWXU):
                flag = True
                print(f"Interactive user {user} has a home directory of {homeDirs[user]} with invalid permissions")

    if not flag:
        print("Audit passed for 7.2.9.\n")
    else:
        print("Audit failed for 7.2.9.\n")

def Check_7_2_10():
    print("Running audit for 7.1.18...")

    flag = False

    if not flag:
        print("Audit passed for 7.2.10.\n")
    else:
        print("Audit failed for 7.2.10.\n")
