#!/usr/bin/env python3

import subprocess
import json
import re
import os
import stat

def ArrayToText(array):
    if len(array) == 0: 
        return ""
    elif len(array) == 1:
        return array[0]
    elif len(array) == 2:
        return f"{array[0]} and {array[1]}"
    else:
        i = 0
        s = ""

        while i < len(array) - 1:
            s += f"{array[i]}, "
            i += 1

        s += f"and {array[-1]}"
        return s

def IsEOF(stream):
    currIndex = stream.tell()
    stream.read(1) # try to read 1 char

    # if no more to read
    if currIndex == stream.tell():
        return True
    # if more to read
    else:
        # reset to current pos
        stream.seek(currIndex)
        return False

def GetDirExclusions():
    excludedTypes = ["nfs", "proc", "cifs", "smb", "vfat", "iso9660", "efivarfs", "selinuxfs", "ncpfs"]
    excludedRootDirs = {"/run", "/tmp", "/var/tmp", "/sys", "/snap", "/boot/efi", "/proc"}
    excludedGlobDirs = ["/containers/storage/", "/containerd/", "/kubelet/"]

    mounts = subprocess.run("findmnt --json -Dkeno fstype,target", shell=True, capture_output=True)
    mounts = json.loads(mounts.stdout.decode())

    # cache additional directories to ignore
    for mount in mounts["filesystems"]:
        if mount["fstype"] in excludedTypes:
            excludedRootDirs.add(mount["target"])

    return excludedRootDirs, excludedGlobDirs

def GetDirExclusionsWithOptions():
    excludedTypes = ["nfs", "proc", "cifs", "smb", "vfat", "iso9660", "efivarfs", "selinuxfs", "ncpfs"]
    excludedRootDirs = {"/run/user", "/proc"}
    excludedOptions = ["noexec", "nosuid"]

    mounts = subprocess.run("findmnt --json -Dkeno fstype,target,options", shell=True, capture_output=True)
    mounts = json.loads(mounts.stdout.decode())

    # cache additional directories to ignore
    for mount in mounts["filesystems"]:
        options = mount["options"].split(",")

        if mount["fstype"] in excludedTypes:
            excludedRootDirs.add(mount["target"])
        elif "noexec" in options or "nosuid" in options: 
            excludedRootDirs.add(mount["target"])

    return excludedRootDirs

def CollectInteractiveHomeDirs():
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

    return homeDirs

def GetMode(path):
    try:
        mode = os.lstat(path)

        if (stat.S_ISDIR(mode.st_mode)):
            return mode
        else:
            return -1
    except FileNotFoundError:
        return -1

def ParseDeb822(file):
    counter = 0
    stanzas = {}
    lines = []

    with open(file, 'r') as f:
        while True:
            # read line from file
            line = f.readline()

            # append to lines[] if not a comment or newline
            if re.match(r"^[^#\n].*", line):
                lines.append(line)

            # append to stanzas dict if line is a newline and block of lines > 0
            if line == '\n' and len(lines) > 0:
                stanzas[counter] = lines
                lines = []
                counter += 1

            # if EOF, return
            if IsEOF(f):
                # append remaining lines if data exists
                if len(lines) > 0:
                    stanzas[counter] = lines
                return stanzas
