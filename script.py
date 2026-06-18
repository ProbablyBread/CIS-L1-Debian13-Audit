#!/usr/bin/python3

import subprocess
import pathlib
import os
import re

def Check_5_2_5():
    print("Running audit for 5.2.5...")

    sudoersFiles = ["/etc/sudoers"]
    flag = False

    for filepath in pathlib.Path("/etc/sudoers.d").glob("*"):
        sudoersFiles.append(filepath)

    for file in sudoersFiles:
        with open(file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            if re.match(line, '^[^#].*\\!authenticate.*'):
                flag = True
                print(f"Line matched: {line}")

    if not flag:
        print("Audit passed.")

def Check_5_4_1_6():
    pass

def Check_5_4_2_1():
    pass

def Check_5_4_2_2():
    pass

def Check_5_4_2_3():
    pass

def Check_5_4_2_4():
    pass

def Check_5_4_2_5():
    pass

def Check_7_1_11():
    pass

def Check_7_1_12():
    pass

def Check_7_2_3():
    pass

def Check_7_2_4():
	pass

def Check_7_2_5():
	pass

def Check_7_2_6():
	pass

def Check_7_2_7():
	pass

def Check_7_2_8():
	pass

def Check_7_2_9():
	pass

def Check_7_2_10():
	pass

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
