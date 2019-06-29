#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Program:
#  This program ansible playbook run yml file. Aim to add route or del route on router.
# 2019/01/23  jackezhang
# filename: route2run.py
# v0.1 run playbook display ip route on route
# v0.1a add: check ansible playbook process already run



import os
import subprocess
import time

def yml2run(ymlfile):
    #ansible playbook run yml file
    #if ymlfile is none then exit
    if not ymlfile:
        print("none yml need run")
        os._exit(0)
    i = 0
    while i < 30:
        # Check if the ansible playbook process is running
        process="/tmp/playbook.lock"
        #os.system("ps -ef|grep ansible-playbook|grep -v grep >%s" % process)
        if not (os.path.getsize(process)):
            cmd = 'ansible-playbook -i /root/playbooks/local ' + str(ymlfile)
            print(cmd)
            output = subprocess.check_call(cmd, shell=True)
            i = 34
        else:
            print("ansible playbook already run, pls waite")
            time.sleep(3)
            i += 1
    print("yml is over")
    print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))


if __name__ == '__main__':
    ymlpath = "/root/autocmd/playbook/h3c_addroute_new.yml"
    yml2run(ymlpath)
