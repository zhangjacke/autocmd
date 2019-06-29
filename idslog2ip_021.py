#!/usr/bin/env python3
# coding: utf-8
# filename: idslog2ip.py
# Program:
#  This program analysis ids.log then generate ban ip list
# 2019/03/13  jackezhang
# v0.1 read '/var/log/ids.log' and copy code from log2ip.py
# v0.1a use ip2route_077 import  ip2delrouteyml, close yml2run
# v0.2 first handle cve log and cve ip damp time more long, second handle normal log
# v0.21 ids send 2 format log, use try.. except


"""
IDS  log formate
example
Mar  13 10:33:48 10.22.36.9 (none) : {"dt":"VENUS_IDS_0700R0400B20160910132231","level":30,"id":"152321043",
"type":"Alert Log","time":1552444428601,"source":{"ip":"180.97.176.83","port":0,"mac":"4c-09-b4-f6-cf-70"},
"destination":{"ip":"0.0.0.0","port":0,"mac":"00-00-00-00-00-00"},"protocol":"ICMP",
"subject":"SCAN_ICMPɨ▒▒̽▒▒","message":"ICMP scan rate: 16/1s, 180.97.176.83->59.47.54.6, 180.97.176.83->59.47.54.16,
180.97.176.83->59.47.54.15, 180.97.176.83->59.47.54.13, 180.97.176.83->59.47.54.7, 180.97.176.83->59.47.54.11, 180.97.176.83->59.47.54.1,
 180.97.176.83->59.47.54.9, 180.97.176.83->59.47.54.8, 180.97.176.83->59.47.54.3","securityid":"4","attackid":"1004"}

---
db autocmd
desc addressinfo;
+--------------+------------------+------+-----+-------------------+-----------------------------+
| Field        | Type             | Null | Key | Default           | Extra                       |
+--------------+------------------+------+-----+-------------------+-----------------------------+
| id           | int(10) unsigned | NO   | PRI | NULL              | auto_increment              |
| log_date     | timestamp        | NO   |     | CURRENT_TIMESTAMP | on update CURRENT_TIMESTAMP |
| weixie_ip    | varchar(40)      | NO   |     | NULL              |                             |
| peer_ip      | varchar(40)      | NO   |     | NULL              |                             |
| weixie_type  | varchar(100)     | YES  |     | NULL              |                             |
| num          | int(11)          | NO   |     | NULL              |                             |
| repeate_time | int(11)          | YES  |     | 0                 |                             |
| damp_status  | int(11)          | YES  |     | 0                 |                             |
| free_date    | int(11)          | YES  |     | 0                 |                             |
| area         | varchar(40)      | YES  |     | NULL              |                             |
+--------------+------------------+------+-----+-------------------+-----------------------------+
10 rows in set (0.00 sec)
"""

from __future__ import division
import os
import re
import pymysql
import time
from ip2route_078 import checkip, ip2displayyml, ip2addrouteyml
from ban2log_021 import ban2log
import random



LOG_FILE = '/var/log/ids.log'
#LOG_FILE = 'ids1.log'
POSITION_FILE = 'position_ids.log'


def get_position():
    # The first time the log file is read, POSITION-FILE is empty
    if not os.path.exists(POSITION_FILE):
        start_position = str(0)
        # os.path.getsize :Bytes of the file
        end_position = str(os.path.getsize(LOG_FILE))
        # print(start_position, end_position)
        fh = open(POSITION_FILE, 'w')
        fh.write('start_position: %s\n' % start_position)
        fh.write('end_position: %s\n' % end_position)
        fh.close()
        # os._exit(1)
    else:
        fh = open(POSITION_FILE)
        se = fh.readlines()
        # print(se)
        fh.close()
        # Other unexpected circumstances cause the POSITION-FILE content to be not two lines
        if len(se) != 2:
            os.remove(POSITION_FILE)
            os._exit(1)
        # Extract information from location files
        last_start_position, last_end_position = [item.split(':')[1].strip() for item in se]
        start_position = last_end_position
        end_position = str(os.path.getsize(LOG_FILE))
        # Log rotation, start_position > end_position
        print(start_position, end_position)
        if int(start_position) > int(end_position):
            start_position = 0
        # When the log stops rolling
        elif int(start_position) == int(end_position):
            print("none update log ")
            os._exit(1)
        # print start_position,end_position
        fh = open(POSITION_FILE, 'w')
        fh.write('start_position: %s\n' % start_position)
        fh.write('end_position: %s\n' % end_position)
        fh.close()
        # map,Convert string format to int format
    return map(int, [start_position, end_position])


def handle_log(start_position, end_position):
    # open chinese log,There are Chinese in the log, there will be garbled errors, using the appropriate encoding, ignoring the errors
    # log = open(LOG_FILE)
    log = open(LOG_FILE, mode='r',encoding='gbk', errors='ignore')
    log.seek(start_position, 0)
    sip, dip, attname, attnum, attid = "", "", "", "", ''
    devlist, siplist, diplist, attnamelist, attnumlist = [], [], [], [], []
    re_word1 = re.compile(r'VENUS')
    re_word2 = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    # regex for ids.log
    rmonth = r"?P<month>\w+"
    rdate = r"?P<date>\d+"
    rtime = r"?P<time>\S+"
    rhost = r"?P<host>[\d.]*"
    rnone = r"?P<rnone>\S+"
    rdt = r"?P<rdt>\S+"
    rvenus = r"?P<rvenus>\S+"
    rlevel = r"?P<rlevel>\S+"
    rleveln = r"?P<rleveln>\d+"
    rid = r"?P<rid>\S+"
    ridn = r"?P<ridn>\d+"
    rtype = r"?P<rtype>\S+"
    rtypen = r"?P<rtypen>\w+\s\w+"
    rtime2 = r"?P<rtime2>\w+"
    rtime2n = r"?P<rtime2n>\d+"
    rsource = r"?P<rsource>\w+"
    rsip = r"?P<rsip>\w+"
    rsipn = r"?P<rsipn>[\d.]*"
    rsport = r"?P<rsport>\w+"
    rsportn = r"?P<rsportn>\d+"
    rmac = r"?P<rmac>\w+"
    rmacn = r"?P<rmacn>\S+"
    rdestination = r"?P<rdestination>\w+"
    rdip = r"?P<rdip>\w+"
    rdipn = r"?P<rdipn>[\d.]*"
    rdport = r"?P<rdport>\w+"
    rdportn = r"?P<rdportn>\d+"
    rdmac = r"?P<rdmac>\w+"
    rdmacn = r"?P<rdmacn>\S+"
    rprot = r"?P<rprot>\S+"
    rprotn = r"?P<rprotn>\S+"
    rsubject = r"?P<rsubject>\S+"
    rsubjectn = r"?P<rsubjectn>\S+"
    rmessage = r"?P<rmessage>\S+"
    rmessagen = r"?P<rmessagen>.*"
    rsecurityid = r"?P<rsecurityid>\S+"
    rsecurityidn = r"?P<rsecurityidn>\d+"
    rattackid = r"?P<rattackid>\S+"
    rattackidn = r"?P<rattackidn>\d+"

    p = re.compile(r"(%s)\ \ (%s)\ (%s)\ (%s)\ (%s)\ \:\ \{\"(%s)\"\:\"(%s)\",(%s)\"\:(%s),\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:(%s),\"(%s)\"\:\{\"(%s)\"\:\"(%s)\",\"(%s)\"\:(%s),\"(%s)\"\:\"(%s)\"\},\"(%s)\"\:\{\"(%s)\"\:\"(%s)\",\"(%s)\"\:(%s),\"(%s)\"\:\"(%s)\"\},\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\"\}"
        % (rmonth, rdate, rtime, rhost, rnone, rdt, rvenus,
           rlevel, rleveln, rid, ridn, rtype, rtypen,
           rtime2, rtime2n, rsource, rsip, rsipn, rsport, rsportn, rmac, rmacn,
           rdestination, rdip, rdipn, rdport, rdportn, rdmac, rdmacn,
           rprot, rprotn, rsubject, rsubjectn, rmessage, rmessagen,
           rsecurityid, rsecurityidn, rattackid, rattackidn), re.VERBOSE)
    p1 = re.compile(r"(%s)\s+(%s)\ (%s)\ (%s)\ (%s)\ \:\ \{\"(%s)\"\:\"(%s)\",(%s)\"\:(%s),\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:(%s),\"(%s)\"\:\{\"(%s)\"\:\"(%s)\",\"(%s)\"\:(%s),\"(%s)\"\:\"(%s)\"\},\"(%s)\"\:\{\"(%s)\"\:\"(%s)\",\"(%s)\"\:(%s),\"(%s)\"\:\"(%s)\"\},\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\",\"(%s)\"\:\"(%s)\"\}"
        % (rmonth, rdate, rtime, rhost, rnone, rdt, rvenus,
           rlevel, rleveln, rid, ridn, rtype, rtypen,
           rtime2, rtime2n, rsource, rsip, rsipn, rsport, rsportn, rmac, rmacn,
           rdestination, rdip, rdipn, rdport, rdportn, rdmac, rdmacn,
           rprot, rprotn, rsubject, rsubjectn, rmessage, rmessagen,
           rsecurityid, rsecurityidn, rattackid, rattackidn), re.VERBOSE)
    while True:
        current_position = log.tell()
        # print(current_position)
        if current_position >= end_position:
            break
        logline = log.readline()
        #logline = log.readline().decode('gbk').encode('utf-8')
        if re.search(re_word1, logline) and re.search(re_word2, logline):
            #print(logline)
            # print(sip)
            try:
                matchs = p1.match(logline)
                allGroups = matchs.groups()
            except AttributeError:
                print("log format error: AttributeError")
                # matchs = p1.match(logline)
                # allGroups = matchs.groups()
            except TypeError:
                print("log format error: TypeError")
            else:
                #print(allGroups)
                dev = allGroups[3]
                sip = allGroups[17]
                dip = allGroups[24]
                attname = allGroups[32]
                attid = allGroups[38]
                #attnum = 1
                print(dev, sip, dip, attname)
                #for n, i in enumerate(allGroups):
                #    print(n, i)
                if sip and attname and dev:
                    #print("sip and attname and attid is ok")
                    # del same ip
                    if sip not in siplist:
                        #print(sip)
                        devlist.append(dev)
                        siplist.append(sip)
                        diplist.append(dip)
                        attnamelist.append(attname)
    log.close()
    print(len(devlist), len(siplist), len(diplist), len(attnamelist))
    return (devlist, siplist, diplist, attnamelist)


def ip2class(devlist, siplist, diplist, attnamelist):
    # turn banlist into 2 class list, one list include cve-ip, another list include scan ip
    vdevlist, vsiplist, vdiplist, vattnamelist = [], [], [], [],
    ndevlist, nsiplist, ndiplist, nattnamelist = [], [], [], [],
    #print(devlist, siplist, diplist, attnamelist, attnumlist)
    re_word = re.compile(r'CVE')
    for n, name in enumerate(attnamelist):
        if re.search(re_word, name):
            print("CVE threat: " +str(name))
            vdevlist.append(devlist[n])
            vsiplist.append(siplist[n])
            vdiplist.append(diplist[n])
            vattnamelist.append(name)
        else:
            print("normal threat")
            ndevlist.append(devlist[n])
            nsiplist.append(siplist[n])
            ndiplist.append(diplist[n])
            nattnamelist.append(name)
    print(vsiplist, vattnamelist)
    print(nsiplist, nattnamelist)
    return (vdevlist, vsiplist, vdiplist, vattnamelist,
            ndevlist, nsiplist, ndiplist, nattnamelist, )

def ip2drop(banlist, peerlist, namelist, devlist):
    # random drop some ip
    if not banlist:
        os._exit(0)
    banlist2, peerlist2, namelist2, devlist2 = [], [], [], []
    for n, ip in enumerate(banlist):
        # 9/10 banlist to drop
        if random.choice('aaaabaaaaa') == 'b':
            banlist2.append(banlist[n])
            peerlist2.append(peerlist[n])
            namelist2.append(namelist[n])
            devlist2.append(devlist[n])
    print("random drop ip is over, banlist long is: " + str(len(banlist2)))
    return (banlist2, peerlist2, namelist2, devlist2)


def topip(siplist, diplist, attnamelist, attnumlist):
    """select ip from top attnum"""
    print(siplist, attnumlist)
    banlist, peeriplist, bannamelist, bannum = [], [], [], []
    # bannum  = []
    for (i, j) in enumerate(attnumlist):
        if int(j) > 1000:
            banlist.append(siplist[i])
            peeriplist.append(diplist[i])
            bannamelist.append(attnamelist[i])
            bannum.append(j)
    print(banlist, peeriplist, bannamelist, bannum)
    return (banlist, peeriplist, bannamelist, bannum)



def ip2sql(sip, dip, type, dev, cve=0):
    # put ip lists into sql
    if not sip:
        os._exit(0)
    # config damp  base time is 5 minutes
    dam_base = 5
    # if ip is CVE then damp time is more minutes
    if cve == 1:
        dam_base = dam_base * 4
    # Open a database connection
    db = pymysql.connect("localhost", "root", "autocmd@201", "autocmd")
    # Create a cursor object using the cursor() method
    cursor = db.cursor()
    ymlist, peeriplist, namelist, devlist = [], [], [], []
    for n, ip in enumerate(sip):
        # check ip damp status from sql
        sel_sql = "SELECT * FROM addressinfo WHERE weixie_ip = \'%s\'" % (ip)
        # mysql test table addressinfo_test
        #sel_sql = "SELECT * FROM addressinfo_test WHERE weixie_ip = \'%s\'" % (ip)
        cursor.execute(sel_sql)
        result = cursor.fetchall()
        if result:
            print(str(ip) + "  in SQL weixie_ip, check damp status")
            for row in result:
                table_id = row[0]
                rep_time = row[6] + 1
                dam_stat = row[7]
                #print(table_id, rep_time, dam_stat)
                #print(dam_base * rep_time ** 2)
                # free_date = now time + 5* n**2. (//60 :minute)
                sum_time = int(time.time()) // 60 + dam_base * rep_time ** 2
                if dam_stat == 0:
                    print("damp status=0")
                    ymlist.append(ip), peeriplist.append(dip[n]), namelist.append(type[n]), devlist.append(dev[n])
                    update_sql = "UPDATE addressinfo SET log_date = NOW(), peer_ip = \'%s\', weixie_type = \'%s\', "\
                                  "area = \'%s\',  damp_status = 1, repeate_time = repeate_time + 1, "\
                                  "free_date = \'%s\'  WHERE id = \'%s\'" % \
                                  (dip[n], type[n], dev[n], sum_time, table_id)
                    # mysql test table addressinfo_test
                    #update_sql = "UPDATE addressinfo_test SET log_date = NOW(), peer_ip = \'%s\', weixie_type = \'%s\', " \
                    #             "area = \'%s\',  damp_status = 1, repeate_time = repeate_time + 1, " \
                    #             "free_date = \'%s\'  WHERE id = \'%s\'" % \
                    #             (dip[n], type[n], dev[n], sum_time, table_id)
                    print(update_sql)
                    cursor.execute(update_sql)
                    db.commit()
                elif dam_stat == 1:
                    print("damp status=1")
                    update_sql = "UPDATE addressinfo SET log_date = NOW(), peer_ip = \'%s\', weixie_type = \'%s\', "\
                                 "area = \'%s\',  damp_status = 1, repeate_time = repeate_time + 1, "\
                                 "free_date = %s  WHERE id = %s" % \
                                 (dip[n], type[n], dev[n], sum_time, table_id)
                    # mysql test table addressinfo_test
                    #update_sql = "UPDATE addressinfo_test SET log_date = NOW(), peer_ip = \'%s\', weixie_type = \'%s\', " \
                    #             "area = \'%s\',  damp_status = 1, repeate_time = repeate_time + 1, " \
                    #             "free_date = %s  WHERE id = %s" % \
                    #             (dip[n], type[n], dev[n], sum_time, table_id)
                    print(update_sql)
                    cursor.execute(update_sql)
                    db.commit()
        else:
            print(str(ip) + " not in SQL weixie_ip, add ip in weixie_ip sql")
            ymlist.append(ip), peeriplist.append(dip[n]), namelist.append(type[n]), devlist.append(dev[n])
            # free_date = now time + 5. (//60 :minute)
            sum_time = int(time.time()) // 60 + dam_base
            insert_sql = "INSERT INTO addressinfo (log_date, "\
                       "weixie_ip, peer_ip, weixie_type, area, repeate_time, damp_status, free_date) "\
                       "VALUES (NOW(), \"%s\", \"%s\", \"%s\", \"%s\", 1, 1, %s)" % \
                       (ip, dip[n], type[n], dev[n], sum_time)
            # mysql test table addressinfo_test
            #insert_sql = "INSERT INTO addressinfo_test (log_date, "\
            #           "weixie_ip, peer_ip, weixie_type, area, repeate_time, damp_status, free_date) "\
            #           "VALUES (NOW(), \"%s\", \"%s\", \"%s\", \"%s\", 1, 1, %s)" % \
            #           (ip, dip[n], type[n], dev[n], sum_time)
            cursor.execute(insert_sql)
            db.commit()
    # Close the database connection
    db.close()
    print(ymlist, peeriplist, namelist, devlist)
    print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
    return (ymlist, peeriplist, namelist, devlist)

if __name__ == '__main__':
    # get last read position in log file
    start_position, end_position = get_position()
    # handle log then create ip,attact name, num lists
    hlist, slist, dlist, namelist = handle_log(start_position, end_position)
    vdevlist, vsiplist, vdiplist, vattnamelist, \
    ndevlist, nsiplist, ndiplist, nattnamelist = ip2class(hlist, slist, dlist, namelist)
    if vattnamelist and vsiplist:
        # first handle CVE list
        print("INTO checkip: CVE")
        # check banip by chukouip and whitelist
        iplist, peerlist, typelist, idslist = checkip(vsiplist, vdiplist, vattnamelist, vdevlist, check10=1)
        # check ip damp status before put banip ,attact name,num into mysql
        ymlist, peeriplist, namelist, devlist = ip2sql(iplist, peerlist, typelist, idslist, cve=1)
        # create add route playbook yml file and run ansible playbook
        ymlpath = ip2addrouteyml(ymlist)
        # create threat ip log
        ban2log(ymlist, peeriplist, namelist, devlist, 1)
    # second handle normal list
    # check banip by chukouip and whitelist
    iplist, peerlist, typelist, idslist = checkip(nsiplist, ndiplist, nattnamelist, ndevlist, check10=1)
    if iplist and len(iplist) >= 30:
        print("banlist long: " + str(len(iplist)) + "> 30, so need to drop some ip")
        iplist, peerlist, typelist, idslist = ip2drop(iplist, peerlist, typelist, idslist)
    # check ip damp status before put banip ,attact name,num into mysql
    ymlist, peeriplist, namelist, devlist = ip2sql(iplist, peerlist, typelist, idslist)
    # create add route playbook yml file and do ansible playbook
    ymlpath = ip2addrouteyml(ymlist)
    # create threat ip log
    ban2log(ymlist, peeriplist, namelist, devlist, 1)

