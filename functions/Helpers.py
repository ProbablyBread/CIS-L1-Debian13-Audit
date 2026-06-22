#!/usr/bin/env python3

import subprocess
import json

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

def ParseDeb822(file):
    counter = 0
    stanzas = {}
    lines = []

    with open(file, 'r') as f:
        while True:
            line = f.readline()
            lines.append(line)

            # test if newline
            if line == '\n':
                stanzas[counter] = lines
                lines.clear()
                counter += 1

            # test if EOF and exit loop
            if not line:
                stanzas[counter] = lines
                break

    return stanzas
