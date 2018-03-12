#/usr/bin/env python
#Forensics Analysis for TLEN 5540
#Team Members: Paxaj Shukla, Sampreet Kishan, and Dilara Madinger
#Contact : sampreet.kishan@colorado.edu ; dilara.madinger@colorado.edu ; paxaj.shukla@colorado.edu

# Automount drive and hash with a table of users and times.
# Timeline of file changes
# Visualize IP addresses

from subprocess import *
import subprocess 
import argparse
import sys
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt

try:
    from prettytable import PrettyTable as pt
except:
    print("The python module prettyTable is not installed")
    sys.exit()


def autoMOUNT(spath, mpath):
    #Let's check if the device is mounted or not
    command ="mount"
    run =subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output=run.communicate()[0]
    print("\n\n\tAUTOMOUNT\n")
    string=spath+" on "+mpath

    if(string in output):
        print("Already mounted. Skipping mounting")
    else:
        subprocess.call(["mount", "-oro", spath, mpath])

def DHCPIP(mpath):
    print("The DHCP IP offered/accepted")
    command = "cat "+mpath+ "/var/log/syslog | grep dhcp | grep -E \'OFFER|ACK\' | awk \'{print $1,$2,$3,$7,$8,$9}\'"
    run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = run.communicate()[0]
    table = pt(["Date", "IP Offered/Accepted"])
    output = output.splitlines()
    ip={}
    obj=[]
    for row in output:
        row=row.split(" ")
        table.add_row([str(row[0]+" "+row[1]+" "+row[2]), str("("+row[3]+") "+row[5])])
        if(row[5] in ip.keys()):
            ip[row[5]]=ip[row[5]]+1
        else:
            ip[row[5]]=1
        if(row[5] not in obj):
            obj.append(row[5])

    print(table)
    y_pos=np.arange(len(ip))
    no_ip=[]
    y=[]
    for key in ip.keys():
        y.append(ip[key])
        
    plt.bar(y_pos,y,align='center',alpha=0.5)
    obj=tuple(obj)
    plt.xticks(y_pos,obj,rotation='vertical')
    plt.xlabel("IPs offered by the DHCP server")
    plt.ylabel("Number of IPS") 
    plt.show()

def lastlogin(mpath, user):
    command = "cat "+ mpath +"/var/log/auth.log | grep \"session opened\" | grep pi | awk \'{print $1,$2,$3, $11}\' | head -n 20"
    run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = run.communicate()[0]
    print("\nThe last 20 logins were:")
    table = pt(["Date", "User"])
    output = output.splitlines()
    for row in output:
        table.add_row([row[0:15], row[15:len(row)]])
    print(table)


def file_change(mpath):
    command = "find " + mpath + "/etc -mtime +1 -ls | awk \'{print $8,$9,$10,$11}\' | grep -v \"20[0-1][0-9]\" | grep -E \'conf|passwd|init|systemd|sysctl\'"
    run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = run.communicate()[0]
    table = pt(["Date Modified", "File"])
    output = output.splitlines()
    print("Files changed in 2017")
    for row in output:
        row = row.split(" ")
        date = row[0] + " " + row[1] + " " +row[2]
        table.add_row([date, row[3]])
    print(table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spath", help="path to the image")
    parser.add_argument("--mpath", help="mount path")
    parser.add_argument("--user", help="The user to check last login for")
    args = parser.parse_args()
    try:
        mpath=args.mpath
        spath=args.spath
        user=args.user
    except:
        print("something wrong with passing arguments");
    print("\n\n\tNetwork security Lab's Final Project: Forensics")
    print("---------------------------------------------------------------\n")
    autoMOUNT(spath, mpath)
    print("---------------------------------------------------------------\n")
    lastlogin(mpath, user)
    print("---------------------------------------------------------------\n")
    file_change(mpath)
    print("---------------------------------------------------------------\n")
    DHCPIP(mpath)
if __name__ == "__main__":
    main()
