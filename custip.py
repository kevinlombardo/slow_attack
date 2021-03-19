#!/usr/bin/python3
import socket
import struct

class IPPacket:
 def __init__(self, dst='127.0.0.1', src='192.168.1.101'):
  self.dst = dst
  self.src = src
  self.raw = None
  self.create_ipv4_fields_list()

 def assemble_ipv4_fields(self):
  self.raw = struct.pack('!BBHHHBBH4s4s' , 
   self.ip_ver,   # IP Version 
   self.ip_dfc,   # Differentiate Service Feild
   self.ip_tol,   # Total Length
   self.ip_idf,   # Identification
   self.ip_flg,   # Flags
   self.ip_ttl,   # Time to leave
   self.ip_proto, # protocol
   self.ip_chk,   # Checksum
   self.ip_saddr, # Source IP 
   self.ip_daddr  # Destination IP
   )
  return self.raw


 def create_ipv4_fields_list(self):

  # ---- [Internet Protocol Version] ----
  ip_ver = 4
  ip_vhl = 5

  self.ip_ver = (ip_ver << 4 ) + ip_vhl

  # ---- [ Differentiate Servic Field ]
  ip_dsc = 0
  ip_ecn = 0

  self.ip_dfc = (ip_dsc << 2 ) + ip_ecn

  # ---- [ Total Length]
  self.ip_tol = 0

  # ---- [ Identification ]
  self.ip_idf = 54321

  # ---- [ Flags ]
  ip_rsv = 0
  ip_dtf = 0
  ip_mrf = 0
  ip_frag_offset = 0

  self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)

  # ---- [ Total Length ]
  self.ip_ttl = 255

  # ---- [ Protocol ]
  self.ip_proto = socket.IPPROTO_TCP

  # ---- [ Check Sum ]
  self.ip_chk = 0

  # ---- [ Source Address ]
  self.ip_saddr = socket.inet_aton(self.src)

  # ---- [ Destination Address ]
  self.ip_daddr = socket.inet_aton(self.dst)

  return
