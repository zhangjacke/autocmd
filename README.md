# autocmd
This program is used to receive intrusion detection system（IDS） threat information and then block the threat IP.

Features: 
1. In order to achieve automatic defense against network attacks, this program realizes the linkage between network security devices and network devices; 
2. Punitive blocking of network attacks and automatic release of resources after the punishment time; 
3. Punishment strategies are implemented according to the severity of network attacks.

User Guide:
Pre-preparation: 
1. installing ansible and managing routers of Internet outlet location; 
2. receiving intrusion detection system (IDS) network attack logs and filtering low-level logs;

1. Call blocking main program idslog2ip.py by means of timed tasks
2. Call release main program ip2free.py in the way of timed tasks
