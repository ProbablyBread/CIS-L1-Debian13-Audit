#!/usr/bin/python3
from functions import Checks

import os
import sys

if __name__ == "__main__":
    if os.geteuid() == 0: 
        # if no arguments, run all by default
        if len(sys.argv) == 1:
            Checks.RunAll()
        # if 1 argument, run only the specified check
        elif len(sys.argv) == 2:
            Checks.RunCheck(sys.argv[1])
        else:
            print("Unable to parse arguments.")
            print("Provide 0 arguments to run all audits, or 1 argument to run the specified audit.")
    else:
        print("Please run this script as root.")
