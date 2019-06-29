#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Program:
#  This program fenxi ip.csv then static route file
# 2019/01/23  jackezhang
# filename: ip2route.py
# v0.5 compare internal choukou ip
# v0.6 create ansible playbook file: h3c-disroute.yml or h3c-addroute.yml
# v0.7 change to def format
# v0.73a add whitelist in def checkip
# v0.74 add blacklist in def checkip
# v0.75 playbook add route yml  and del route yml
# v0.76 def checkip ,check sip in LAN 10.0.0.0 or 11.0.0.0
# v0.77 error: bigbanlist do ansible playbook. split big banlist into small list in def ip2addrouteyml and ip2delrouteyml
# v0.78 add ids device ip and  del numlist in def checkip
# v0.79 fix: create yml file include time in filename


"""
chukou.csv for internet public ip of company
['1.85.20.0', '1.85.51.0', '101.95.30.0']
whitelist.csv  for important server
125.32.26.4,dns
['125.32.26.4', '10.34.62.9']
blacklist.csv for bad ip from cisco talos
https://www.talosintelligence.com/documents/ip-blacklist
149.202.170.60,23.129.64.101 ...
"""


import csv
import re
import os
import time
import shutil
from route2run_01 import yml2run

def ip2displayyml(iplist):
    # ip turn into route then create yml file
    # if banlist is none then exit
    if not iplist:
        print("none ip need ban")
        os._exit(0)
    # cp basic yml to new.yml
    display_basic = "/root/autocmd/playbook/h3c_display_basic.yml"
    display_new = "/root/autocmd/playbook/h3c_display_new.yml"
    # cp basic yml file and rename
    shutil.copy(display_basic, display_new)
    # handle iplist
    for ip in iplist:
        print("create yml file for: " +str(ip))
        # add ip route x.x.x.x/32 in new.yml
        with open(display_new, 'a') as ymlf:
            ymlf.write("          display ip routing-table  %s 32\n"%ip)
    return(display_new)

def ip2addrouteyml(iplist):
    # ip turn into route then create yml file
    # if banlist is none then exit
    if not iplist:
        print("none ip need ban")
        os._exit(0)
    # cp basic yml to new.yml
    addroute_basic = "/root/autocmd/playbook/h3c_addroute_basic.yml"
    #addroute_new = "/root/autocmd/playbook/h3c_addroute_new.yml"
    # cp basic yml file and rename
    #shutil.copy(addroute_basic, addroute_new)
    # split list into small list, small list include 25 ip
    n = 25
    clist = [iplist[i:i+n] for i in range(0, len(iplist), n)]
    #print(clist)
    # handle banlist
    for slist in clist:
        # create yml file include time in filename
        tim = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
        #print(tim)
        addroute_new = "/root/autocmd/playbook/tmp/h3c_addroute_" + tim + ".yml"
        #print(addroute_new)
        # cp basic yml file and rename
        shutil.copy(addroute_basic, addroute_new)
        for ip in slist:
            print("create yml file for: " +str(ip))
            with open(addroute_new, 'a') as ymlf:
                ymlf.write("          ip route-static %s 32 NULL0\n" % ip)
        print("doing ansible playbook")
        # playbook run yml file
        yml2run(addroute_new)
        time.sleep(0.5)
    return addroute_new


def ip2delrouteyml(iplist):
    # ip turn into route then create yml file
    # if banlist is none then exit
    if not iplist:
        print("none ip need ban")
        os._exit(0)
    # cp basic yml to new.yml
    delroute_basic = "/root/autocmd/playbook/h3c_delroute_basic.yml"
    #delroute_new = "/root/autocmd/playbook/h3c_delroute_new.yml"
    # splite list into small list, small list include 25 ip
    n = 25
    clist = [iplist[i:i + n] for i in range(0, len(iplist), n)]
    #print(clist)
    # handle banlist
    for slist in clist:
        # create yml file include time in filename
        tim = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
        #print(tim)
        delroute_new = "/root/autocmd/playbook/tmp/h3c_delroute_" + tim + ".yml"
        #print(delroute_new)
        # cp basic yml file and rename
        shutil.copy(delroute_basic, delroute_new)
        for ip in slist:
            print("create yml file for: " + str(ip))
            # add ip route x.x.x.x/32 in new.yml
            with open(delroute_new, 'a') as ymlf:
                ymlf.write("          undo ip route-static %s 32 NULL0\n" % ip)
        with open(delroute_new, 'a') as ymlf:
            ymlf.write("          quit\n")
        print("doing ansible playbook")
        # playbook run yml file
        yml2run(delroute_new)
        time.sleep(0.5)
    return delroute_new

def changip2mask(ipline):
    # change ip x.x.x.x into ip route-static x.x.x.x 32
    # ipline = ""
    fname ="h3c-addroute_" + time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time())) + ".txt"
    # print(fname)
    # fname2 ="h3c-disroute_" + time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time())) + ".txt"
    fname2 ="h3c-disroute.yml"
    # ipline = re.sub(r'[\d]{1,3}$',' 32 NULL0',ipline)
    ipline1 = 'ip route-static ' + ipline + ' 32 NULL0'
    print(ipline1)
    ipline2 = 'display ip route-table ' + ipline + ' 32'
    with open(fname, 'a') as txt_tmp:
        txt_tmp.write("%s\n"%ipline1)
    with open(fname2, 'a') as txt_tmp2:
        txt_tmp2.write("%s\n"%ipline2)

def checkip(banlist, peeriplist, namelist, devlist, check10=0):
    # judge banip in internet chukou ip
    # read internal chukou ip .csv file
    ck_ip = "chukou.csv"
    with open(ck_ip) as ck_ip:
        # open chukou.csv file
        ck_reader = csv.reader(ck_ip)
        # get ip address
        ck_highs = [ck_row[0] for ck_row in ck_reader]
    # read internal whitelist ip .csv file
    white_ip = "whitelist.csv"
    with open(white_ip) as wt_ip:
        # open whitelist.csv file
        wt_reader = csv.reader(wt_ip)
        # get ip address
        white_list = [wt_row[0] for wt_row in wt_reader]
    # read blacklist ip .csv file
    black_ip = "blacklist.csv"
    with open(black_ip) as bl_ip:
        # open blacklist.csv file
        bl_reader = csv.reader(bl_ip)
        # get ip address
        black_list = [bl_row[0] for bl_row in bl_reader]
    #print(black_list)
    ymldevlist, ymllist, ymlpeeriplist, ymlnamelist = [], [], [], [],
    #big_h = ""
    delist = []
    #　when check10=1 then check banlist include 10.0.0.0 or 11.0.0.0 or 0.0.0.0
    if check10 == 1:
        print("check ip 10 or 11")
        #re_word2 = re.compile(r'[0-9]{1,3}')
        re_word2 = re.compile(r'(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))')
        for i, sip in enumerate(banlist):
            print(sip)
            big_h = re.search(re_word2, sip).group()
            #big_h = big_h.group()
            #print(big_h)
            if big_h == '10' or big_h == '11' or big_h == '0':
                print(banlist[i] +" is LAN address")
                delist.append(i)
        # print(delist)
        # Inverted deletion of elements in a list
        for d in delist[::-1]:
            devlist.pop(d)
            banlist.pop(d)
            peeriplist.pop(d)
            namelist.pop(d)
        print(banlist, peeriplist, namelist, devlist)
    # check blacklist include banip
    # check  internet chukou and whitelist include banip and peerip
    for n, bip in enumerate(banlist):
        # change ip x.x.x.x into x.x.x.0
        bip_mask = re.sub(r'[\d]{1,3}$', '0', bip)
        pip_mask = re.sub(r'[\d]{1,3}$', '0', peeriplist[n])
        if bip in black_list:
            ymldevlist.append(devlist[n])
            ymllist.append(bip)
            ymlpeeriplist.append(peeriplist[n])
            ymlnamelist.append(namelist[n])
            print("this ip in blacklist : " + bip )
        elif bip_mask in ck_highs or pip_mask in ck_highs:
            print("this sourceip or peerip in chukou  ip list: " + bip_mask + " or " + pip_mask)
            pass
        elif bip in white_list or peeriplist[n] in white_list:
            print("this sourceip or peerip in whitelist ip list: " + bip + ", " + peeriplist[n])
            pass
        else:
            ymldevlist.append(devlist[n])
            ymllist.append(bip)
            ymlpeeriplist.append(peeriplist[n])
            ymlnamelist.append(namelist[n])
            print("this ip not in choukou and whitelist : " + bip + "," + peeriplist[n])
    print(ymllist, ymlpeeriplist, ymlnamelist, ymldevlist)
    return (ymllist, ymlpeeriplist, ymlnamelist, ymldevlist)


if __name__ == '__main__':
    idslist = ["10.22.35.9", "10.22.35.9", "10.22.35.9", "10.22.35.9", "10.22.35.9"]
    baniplist = ["101.2.2.1", "1.85.51.2", "125.32.26.4", "10.106.5.5", "149.202.170.60"]
    peeriplist = ["125.32.26.4", "10.34.6.10", "101.95.30.8", "211.2.2.2", "202.106.196.115"]
    namelist = ["Suspected Scan", "Web Crawler", "CMD Inject", "Suspected Scan", "Web Crawler"]
    numlist = [1019, 1010, 1018, 2112, 1234]
    ymlist, peerlist, typelist, devlist = checkip(baniplist, peeriplist, namelist, idslist, check10=1)
    # ip2displayyml(ymlist)
    #ip2addrouteyml(ymlist)
    #ip2delrouteyml(ymlist)

