#!/apps/mwauto/python/3.8.5/bin/python3

import socket
import sqlite3
import re
import dpkt
import argparse
import time

#SETTINGS

#define local IP to monitor
#LOCAL_IP = '155.6.2.91'

#RULES
#only single flags supported at this time

#rule signature 1: normal browsing sesssion (FIN set at the end)
normalsig = \
'o,P,100:' + \
'PACKETS:' + \
'o,F,0:'

#rule signature 2: script / tool based enumeration (small requests in, small 404 response)
enumerationsig = \
'i,P,200:' + \
'o,P,200:' + \
'i,A,200:' + \
'i,P,200:' + \
'o,P,200:' + \
'i,A,200:' + \
'i,P,200:' + \
'o,P,200:' + \
'i,A,200:' + \
'i,P,200:' + \
'o,P,200:'

#rule signature 3: attack traffic (small requests coming in to keep alive connection)
attacksig = \
'i,P,200:' + \
'o,A,5:' + \
'i,P,200:' + \
'o,A,5:' + \
'i,P,200:' + \
'o,A,5:' + \
'i,P,200:' + \
'o,A,5:'

#rule signature 4: retransmissions? (many incoming requests with no responses)
retrans = \
'i,P,0:' + \
'i,P,0:' + \
'i,P,0:' + \
'i,P,0:' + \
'i,P,0:' + \
'o,R,0:'


rules = {'NORMAL TRAFFIC' :normalsig, 'ENUMERATION TOOL': enumerationsig, 'ATTACK TOOL': attacksig, 'RETRANSMISSION': retrans}

#messy regex generator
#o,(?=(.*A){1})(?=(.*P){1}).*,(?P<SIZE1>[^:]*):
regexs = {}
for k, a in rules.items():
  ra = a.split(':')
  rgx = ''
  rulecount = 0
  for rule in ra:
    rulecount += 1
    rg = re.search('([i|o]),([^,]*),([^:]*)', rule)
    if rg and rg.groups:
      #build first match
      rgx += rg.groups(0)[0] + ','
      #build second match
      rgx += '(' + rg.groups(0)[1]
      #for character in rg.groups(0)[1]:
      #  rgx += character + '|'
      rgx += ').?,'
      #build third match
      rgx += f'(?P<SIZE{str(rulecount)}>[^:]*):'
    rp = re.search('PACKETS', rule)
    if rp and rp.groups:
      rgx +=  f'(?P<PACKETS{str(rulecount)}>.*):'
  regexs.update({k: rgx})
  rgx = ''

'''
for k, v in regexs.items():
  print(f'regex {v}')
  print(f'rule {rules[k]}')
'''

mpool = {}
PACKETS = 0

def check_sig(ipsocket, sig):
  global regexs
  global rules

  matched = False

  for k, rgx in regexs.items():
    msig = re.search(rgx, sig)
    if msig and msig.groups:
      # found match
      rule = re.search(rgx, rules[k])

      #further validation

      #check sizes for constraints
      sizematch = False

      #how to handle no constraints (0 size in the rule)? check to see if there is at least 1 constraint
      for kg, v in msig.groupdict().items():
        if kg[0:4] == 'SIZE':
          packetsizecheck = int(v) - int(rule[kg])
          #check all for conditions, all have to meet
          if int(rule[kg]) == 0:
            #do not care about size, so this is a match
            sizematch = True
          elif packetsizecheck < 0:
            #found a packet that exceeds size
            sizematch = True
          else:
            #packets did not exceed size, mark as OK
            sizematch = False

      if sizematch:
        print(f'{ipsocket} matches {k} pattern')
        matched = True
        return 1

  if not matched:
    print(f'{ipsocket} did not match a pattern')
    print(sig)


def evaluate(conn):
  #get all sockets and loop through
  s_sql = '''SELECT DISTINCT(ipsocket) FROM sessions'''
  cur = conn.cursor()
  cur.execute(s_sql)
  ipsocketrows = cur.fetchall()
  for ipsocketrow in ipsocketrows:
    ipsocket = ipsocketrow[0]
    seq_check = 0
    sig = ''

    get_sql = ''' SELECT ipsocket, direction,src, dst, sport, dport, seq, ack, flags, length FROM sessions WHERE ipsocket = ? ORDER BY ts'''
    cur.execute(get_sql, (ipsocket,))
    sessionrows = cur.fetchall()
    for row in sessionrows:
      ipsocket, direction, src, dst, sport, dport, seq, ack, flags, length  = row

      if seq == 0 or ack == 0:
        #include if outgoing RST packet
        if direction == 'o' and flags == 'R':
          sig += direction + ',' + flags + ',' + str(length) + ':'
        else:
          #skip the SYN
          pass
      elif abs(seq - seq_check) > 10000000 and seq_check > 0:
        #match old session sig
        check_sig(ipsocket, sig)

        #start new session
        sig = direction + ',' + flags + ',' + str(length) + ':'
        seq_check = seq
      else:
        sig += direction + ',' + flags + ',' + str(length) + ':'

        seq_check = seq

    #print last sig
    check_sig(ipsocket, sig)


def insert(conn, ipsocket, direction, src, dst, sport, dport, seq, ack, flags, uri, status, length, ts):
  global PACKETS
  PACKETS += 1
  # insert
  isql = ''' INSERT INTO sessions(ipsocket, direction, src, dst, sport, dport, seq, ack, flags, uri, status, length, ts)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) '''
  cur = conn.cursor()
  cur.execute(isql, (ipsocket, direction, src, dst, sport, dport, seq, ack, flags, uri, status, length, ts,))

  if PACKETS % 100000 == 0:
    print(f'{PACKETS} packets processed.')
    conn.commit()

def create_conn(db):
  conn = None
  # try:
  #conn = sqlite3.connect(db)
  conn = sqlite3.connect(":memory:")

  # except:
  #  print('error')
  return conn

def init_db(conn):
  drop_table = "DROP TABLE IF EXISTS sessions"
  sql_create_port_table = """ CREATE TABLE IF NOT EXISTS sessions(
                                      id integer PRIMARY KEY,
                                      ipsocket text NOT NULL,
                                      direction text NOT NULL,
                                      src text NOT NULL,
                                      dst text NOT NULL,
                                      sport int NOT NULL,
                                      dport int NOT NULL,
                                      seq int NOT NULL,
                                      ack int NOT NULL,
                                      flags text NOT NULL,
                                      uri text NOT NULL,
                                      status text NOT NULL,
                                      length int NOT NULL,
                                      ts float NOT NULL
                                  ); """
  c = conn.cursor()
  c.execute(drop_table)
  c.execute(sql_create_port_table)
  c.execute('CREATE INDEX ipsocket ON sessions(ipsocket)')

def processpkt(conn, ts, eth):
  global LOCAL_IP
  ipdata = eth.data
  tcpdata = ipdata.data

  #flags = tcpdata.flags
  flags = ''

  fd = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32}
  for f in fd:
    if fd[f] & tcpdata.flags:
      flags += f

  src = socket.inet_ntoa(ipdata.src)
  dst = socket.inet_ntoa(ipdata.dst)
  sport = tcpdata.sport
  dport = tcpdata.dport
  ack = tcpdata.ack
  length = len(tcpdata.data)

  if src == LOCAL_IP:
    direction = 'o'
    ipsocket = dst + ':' + str(dport)
    seq = tcpdata.ack
  else:
    direction = 'i'
    ipsocket = src + ':' + str(sport)
    seq = tcpdata.seq

  req = resp = uri = status = ''

  try:
    req = dpkt.http.Request(tcpdata.data)
  except:
    pass
  try:
    resp = dpkt.http.Response(tcpdata.data)
  except:
    pass

  if req:
    uri = req.uri
  if resp:
    status = resp.status

  insert(conn, ipsocket, direction, src, dst, sport, dport, seq, ack, flags, uri, status, length, ts)

if __name__ == "__main__":
  global LOCAL_IP
  ####Arg parser
  stomp_parser = argparse.ArgumentParser(description='Make sure you have the correct arguments')
  ####Arg parser arguments
  stomp_parser.add_argument('--IP',
                            required=True,
                            type=str,
                            help='LOCAL_IP address of target')
  stomp_parser.add_argument('--FILE',
                            required=True,
                            type=str,
                            help='which file to scan')
  ####Execute the parse_args() method
  args = stomp_parser.parse_args()

  LOCAL_IP=args.IP

  conn = create_conn('sessions')
  init_db(conn)

  try:
    f = open(args.FILE, 'rb')
  except:
    print("Enter a filename to scan")

  pcap = dpkt.pcap.Reader(f)

  for ts, buf in pcap:
    pkt = dpkt.ethernet.Ethernet(buf)
    processpkt(conn, ts, pkt)

  conn.commit()
  evaluate(conn)