#!/usr/bin/env python3
# coding: utf-8
# filename: ban2log.py
# Program:
#  This program write some info about bann ip into log file
# 2019/02/11  jackezhang
# v0.1 write '/tmp/autocmd.log'
# v0.11 add peeriplist, namelist
# v0.21 add ids device area in ban2log



import time



def ban2log(banlist, peerlist, namelist, devlist, stat):
    # write ban ip info into autocmd.log. stat = 1 means add weixie ip route on route, stat = 0 means del ip route on route
    LOG_FILE = '/tmp/autocmd.log'
    if stat == 1:
        for n in range(len(banlist)):
            tim = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
            # tim = time.ctime()
            # print(tim)
            with open(LOG_FILE, 'a') as log:
                log.write("time: %s weixie_ip: %s peer_ip: %s subject: %s  area: %s damp_status: ON\n" % (tim, banlist[n], peerlist[n], namelist[n], devlist[n]))
    elif stat == 0:
        for n in range(len(banlist)):
            tim = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
            with open(LOG_FILE, 'a') as log:
                log.write("time: %s weixie_ip: %s peer_id: %s subject: %s damp_status: OFF\n" % (tim, banlist[n], peerlist[n], namelist[n]))
    else:
        pass

def free2log(banlist, stat):
    # write ban ip info into autocmd.log. stat = 1 means add weixie ip route on route, stat = 0 means del ip route on route
    LOG_FILE = '/tmp/autocmd.log'
    if stat == 1:
        for ip in banlist:
            tim = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
            # tim = time.ctime()
            # print(tim)
            with open(LOG_FILE, 'a') as log:
                log.write("time: %s weixie_ip: %s damp_status: ON\n" % (tim, ip))
    elif stat == 0:
        for ip in banlist:
            tim = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
            with open(LOG_FILE, 'a') as log:
                log.write("time: %s weixie_ip: %s damp_status: OFF\n" % (tim, ip))
    else:
        pass


if __name__ == '__main__':
    blist = ['1.2.3.4', '2.2.2.2']
    peeriplist = ["125.32.26.4", "10.34.6.10"]
    namelist = ["Suspected Scan", "Web Crawler"]
    devlist = ["10.22.35.9", "10.33.233.18"]
    ban2log(blist, peeriplist, namelist, devlist, 1)
    #free2log(blist, 0)
