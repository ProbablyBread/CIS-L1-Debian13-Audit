#!/usr/bin/env python3

import subprocess
import json
import re

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

            # continue to next loop if line is a newline
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
