#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Program:
#  This program put threat ip into free
# 2019/02/01  jackezhang
# filename: ip2free.py
# v0.1a write some info about bann ip into log file(tmp/autocmd.log)
# v0.1b use ip2route_077 import  ip2delrouteyml, no yml2run



"""db autocmd
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

import pymysql
import os
import time
from ip2route_078 import ip2displayyml, ip2delrouteyml
from ban2log_023 import free2log


def ip2free():
    # free ip which samp status =1 and free date < now time
    # Open a database connection
    db = pymysql.connect("localhost", "root", "autocmd@201", "autocmd")
    # Create a cursor object using the cursor() method
    cursor = db.cursor()
    ymlist, idlist = [], []
    nowtime = int(time.time()) // 60
    # check ip damp status from sql
    sel_sql = "SELECT id, weixie_ip FROM addressinfo WHERE damp_status = 1 and free_date < %s" % (nowtime)
    cursor.execute(sel_sql)
    result = cursor.fetchall()
    if result:
        # print( "  some ip need free")
        for row in result:
            # print(row)
            idlist.append(row[0])
            ymlist.append(row[1])
    else:
        os._exit(0)
    print(ymlist, idlist)
    if idlist:
        for table_id in idlist:
            update_sql = "UPDATE addressinfo SET damp_status = 0, free_date = 0  WHERE id = %s" % (table_id)
            cursor.execute(update_sql)
            db.commit()
    db.close()
    return (ymlist)


if __name__ == '__main__':
    freeiplist = ip2free()
    #ymlpath = ip2displayyml(freeiplist)
    #freeiplist = ['52.80.9.50']
    # do ansible playbook
    ymlpath = ip2delrouteyml(freeiplist)
    free2log(freeiplist, 0)

