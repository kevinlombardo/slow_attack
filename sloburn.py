#!/apps/mwauto/python/3.8.5/bin/python3

import sys, os, time
import socket
import dpkt
import struct
import custip
import multiprocessing
import copy
from queue import Queue
import threading
import psutil
import array
import re
from datetime import datetime
import argparse

#SETTINGS

#RULES AND MITIGATION
#rule signature 1: too many concurrent connections from single IP
MAX_CONNECTIONS = 50
ENABLE_MAX_CONNECTIONS = True

#rule signature 2: sockets open for too long
MAX_SOCKET_TIME = 300
ENABLE_MAX_SOCKET_TIME = False

#rule signature 3: custom traffic pattern rules

#signature limit size
MAX_SIGNATURE = 128

#mitigation methods
ENABLE_LOG = True
ENABLE_ALERT = False
ENABLE_KILL = True
ENABLE_BLOCK = False

#RULES
#only single ARFP flags supported at this time

#rule 1: normal browsing sesssion
normalsig1 = \
'o,P,100:' + \
'PACKETS:' + \
'o,F,0:'

normalsig2 = \
'o,P,100:' + \
'PACKETS:' + \
'o,R,0:'

#rule 2: attack traffic
attacksig = \
'i,P,200:' + \
'o,A,5:' + \
'i,P,200:' + \
'o,A,5:' + \
'i,P,200:' + \
'o,A,5:'

rules = {'NORMAL TRAFFIC' :normalsig1, 'NORMAL TRAFFIC[R}': normalsig2, 'ATTACK TOOL': attacksig}

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



mpool = {}
filescan = False
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

      for kg, v in msig.groupdict().items():
        if kg[0:4] == 'SIZE':
          packetsizecheck = int(v) - int(rule[kg])
          if packetsizecheck < 0:
            #packet exceeds size threshold, match pattern
            sizematch = True
            break

      if sizematch:
        print(f'{ipsocket} matches {k} pattern')
        matched = True
        return 1

  if not matched:
    return 0

def checksum(pkt):
  # type: (bytes) -> int
  if len(pkt) % 2 == 1:
   pkt += b"\0"
  s = sum(array.array("H", pkt))
  s = (s >> 16) + (s & 0xffff)
  s += s >> 16
  s = ~s

  return s & 0xffff

def kill(src, dest, sport, dport, ack, win):
  sport = int(sport)
  dport = int(dport)
  ack = int(ack)
  win = int(win)

  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  ip = custip.IPPacket(src=src, dst=dest)
  ip.assemble_ipv4_fields()

  #quick workaround to create TCP Packet
  #need to fix
  #tcp = custtcp.TCPPacket(src=src, dst=dest, sport=sport, dport=dport, ack=ack)
  #tcp.assemble_tcp_fields()

  # tcp header fields
  tcp_source = sport	# source port
  tcp_dest = dport	# destination port
  tcp_seq = ack 
  tcp_ack_seq = 0
  tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
  #tcp flags
  tcp_fin = 0
  tcp_syn = 0 
  tcp_rst = 1 
  tcp_psh = 0
  tcp_ack = 0
  tcp_urg = 0
  tcp_window = socket.htons (5840)	#	maximum allowed window size
  tcp_check = 0
  tcp_urg_ptr = 0

  tcp_offset_res = (tcp_doff << 4) + 0
  tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

  # the ! in the pack format string means network order
  tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

  user_data = 'fork'.encode()

  # pseudo header fields
  source_address = socket.inet_aton(src)
  dest_address = socket.inet_aton(dest)
  placeholder = 0
  protocol = socket.IPPROTO_TCP
  tcp_length = len(tcp_header) + len(user_data)

  psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
  psh = psh + tcp_header + user_data;

  tcp_check = checksum(psh)

  # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
  tcp_header = struct.pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + struct.pack('H' , tcp_check) + struct.pack('!H' , tcp_urg_ptr)

  #  # final full packet - syn packets dont have any data
  #  packet = ip_header + tcp_header + user_data

  pkt = ip.raw + tcp_header + user_data
  s.sendto(pkt,(dest, int(dport)))

def mitigate(type, msg, ip, sockdata):
  if ENABLE_LOG:
    print(ip, type, msg)
  if ENABLE_ALERT:
    #NOT IMPLEMENTED
    #add messaging alert (SMTP)
    #add logging to Splunk monitored file for alert
    pass
  if ENABLE_BLOCK:
    #NOT IMPLEMENTED
    #add ip tables rule or blackhole route  #ip route add blackhole 92.243.xx.xx
    pass
  if ENABLE_KILL:
    #this kills the socket
    for s in sockdata:
      kill(ip, LOCAL_IP, int(s), MPORT, int(sockdata[s]['ack']), int(sockdata[s]['win']))

def connected(ip, port):
  found = False
  n = psutil.net_connections()
  for icheck in n:
    if icheck.raddr:
      parseip = icheck.raddr.ip.split(':')[-1]
      if parseip == ip and icheck.raddr.port == int(port):
        found = True
        break
  return found

def killa(removeq, killq):
  #monitor pool and remediate
  global mpool
  while True:
    try:
      if len(mpool) == 0:
        time.sleep(1)

      lpool = copy.deepcopy(mpool)

      for i in lpool:
        # check signature 1: too many connections from single IP
        if ENABLE_MAX_CONNECTIONS:
          totalconnections = len(lpool[i])
          if totalconnections >= MAX_CONNECTIONS:
            mitigate('MAX_CONNECTIONS', f'{i}:{totalconnections}', i, lpool[i])
            if totalconnections >= (4 * MAX_CONNECTIONS):
              #SAFEGUARD too much data, need to reset
              mitigate('MAX_CONNECTIONS', f'{i}:{totalconnections} RESETTING', i, lpool[i])
              removeq.put(i + '::0')
            break

        for s in lpool[i]:
          #check for connection if live scan
          found = connected(i, s)

          sockdata = {s: lpool[i][s]}

          #check signature 2: socket connected too long
          t = datetime.now()
          tt = lpool[i][s]['ts']
          d = t - tt
          if d.seconds > MAX_SOCKET_TIME:
            mitigate('SOCKET TIMEOUT', f'{i}:{totalconnections}', i, sockdata)

          if found:
            #check signature 3: custom rules
            sig = lpool[i][s]['sig']
            if check_sig(i + ':' + str(s), sig):
              mitigate('TRAFFIC PATTERN', f'{i}:{totalconnections}', i, sockdata)

          else:
            #remove it, must have disconnected
            key = str(i + '::' + str(s))
            removeq.put(key)
    except Exception as e:
      print(e)
    time.sleep(1)

def remove(removeq):
  global mpool
  while True:
    time.sleep(1)
    while not removeq.empty():
        k = removeq.get()
        ip, port = k.split('::')

        port = int(port)
        if ip in mpool:
          if port in mpool[ip]:
            mpool[ip].pop(port)
          if port == 0:
            #remove entire IP
            mpool.pop(ip)
        removeq.task_done()

def add(addq):
  global PACKETS
  while True:
    time.sleep(1)
    n = psutil.net_connections()

    while not addq.empty():
        p = addq.get()
        PACKETS += 1
        if PACKETS % 100000 == 0:
          print(f'{PACKETS} processed')
        #      packet = (ip, port, sig, ack, win)

        ip, port, sig, ack, win, ts = p

        #make sure its connected
        found = True
        for icheck in n:
          if icheck.raddr:
            parseip = icheck.raddr.ip.split(':')[-1]
            if parseip == ip and icheck.raddr.port == int(port):
              found = True
              break
        if found:
          if ip in mpool:
            if port in mpool[ip]:
              #update sig ack win ts
              if mpool[ip][port]['ack'] < ack:
                mpool[ip][port]['ack'] = ack
                mpool[ip][port]['win'] = win

              mpool[ip][port]['ts'] = ts
              #sig should be truncated
              sig = mpool[ip][port]['sig'] + sig
              if len(sig) > MAX_SIGNATURE:
                sig = sig[-MAX_SIGNATURE]
              mpool[ip][port]['sig'] = sig
            else:
              # add port to pool
              data = {'sig': sig, 'ack': ack, 'win': win, 'ts': ts}
              newport = {port: data}
              mpool[ip].update(newport)
          else:
            # add IP to mpool
            data = {'sig': sig, 'ack': ack, 'win': win, 'ts': ts}
            newport = {port: data}
            newip = {ip: newport}
            mpool.update(newip)
        addq.task_done()

def processpkt(processq, addq, removeq):
  while True:
    time.sleep(1)
    while not processq.empty():
      pkt, anc  = processq.get()
      eth = dpkt.ethernet.Ethernet(pkt)
      ipdata = eth.data
      tcpdata = ipdata.data

      flags = ''
      ts = datetime.now()

      fd = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32}
      for k, b  in fd.items():
        if b & tcpdata.flags:
          flags += k

      packet = {}

      outgoing = False

      if socket.inet_ntoa(ipdata.src) == LOCAL_IP:
        #outgoing
        outgoing = True
        direction = 'o'
        ip = socket.inet_ntoa(ipdata.dst)
        port = tcpdata.dport
        ack = tcpdata.ack
        win = tcpdata.win
        length = len(tcpdata.data)
      else:
        # incoming
        direction = 'i'
        ip = socket.inet_ntoa(ipdata.src)
        port = tcpdata.sport
        ack = 0
        win = 0
        length = len(tcpdata.data)

      #signature generation
      sig = direction + ',' + flags + ',' + str(length) + ':'
      packet = (ip, port, sig, ack, win, ts)

      if tcpdata.flags & 4 or tcpdata.flags & 1:
        #RST or FIN is set, remove from monitor if outgoing
        if outgoing:
          #VALID TRAFFIC ?
          key = str(ip + '::' + str(port))
          removeq.put(key)
      else:
        # add to q
        addq.put(packet)

      processq.task_done()

def sniff(q):
  SO_TIMESTAMPNS = 35
  s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
  s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
  try:
    while True:
      # Capture packets from network
      pkt=s.recvfrom(65565)
      # do we need to check for tcp?
      prot = pkt[0][23]
      sp = int.from_bytes(pkt[0][34:36],'big')
      dp = int.from_bytes(pkt[0][36:38],'big')
      if sp == MPORT or dp == MPORT:
        processq.put(pkt)
  except KeyboardInterrupt:
    print('exit')

if __name__ == "__main__":
  ####Arg parser
  stomp_parser = argparse.ArgumentParser(description='Make sure you have the correct arguments')
  ####Arg parser arguments
  stomp_parser.add_argument('--IP',
                            required=True,
                            type=str,
                            help='LOCAL_IP address')
  stomp_parser.add_argument('--PORT',
                            required=True,
                            type=str,
                            help='Local PORT')

  ####Execute the parse_args() method
  args = stomp_parser.parse_args()

  # CAPTURE SETTINGS
  # define port to monitor
  MPORT = 80
  # define local IP to monitor
  LOCAL_IP = args.IP

  processq = Queue()
  removeq = Queue()
  addq = Queue()
  killq = Queue()

  tsniff = threading.Thread(target=sniff, args=(processq,))
  tsniff.start()

  toutgoing = threading.Thread(target=processpkt, args=(processq, addq, removeq, ))
  toutgoing.start()

  tadd = threading.Thread(target=add, args=(addq, ))
  tadd.start()

  tremove = threading.Thread(target=remove, args=(removeq, ))
  tremove.start()

  tkilla = threading.Thread(target=killa, args=(removeq, killq, ))
  tkilla.start()
 

