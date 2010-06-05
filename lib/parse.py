#!/usr/bin/env python

from pkt import *
import time
import socket
import struct
import pcap
from tool import *
ip_protocols={
              0:'HOPOPT',
              1:'ICMP',
              2:'IGMP',
              3:'GGP',
              4:'IPv4',
              5:'ST',
              6:'TCP',
              12:'PUP',
              17:'UDP',
              41:'IPv6',
              43:'IPv6-Route',
              44:'IPv6-Frag',
              58:'IPv6-ICMP',
           }
protocols = {
             '\x08\x00':'ip',
             '\x08\x06':'arp',
             '\x86\xdd':'ipv6'
             }
stream_pool = {}


class Pkt:
    def __init__(self, len, data, timest):
        self.timestamp = timest
        self.pkt_len = len
        self.data = data
        self.dict = {}
        self.dict['order'] = []
        
class PoolEntry:
    def __init__(self, pkt, seq, ack, mss):
        self.pkts = [pkt]
        self.a = pkt.dict['ip']['src_address']
        self.b = pkt.dict['ip']['dst_address']
        self.seq_base_a = seq
        self.ack_base_a = ack
        self.mss = mss
        
    def set_mss(self,mss):
        if self.mss < mss:
            self.mss = mss
        
        
        
def __strfmac(data):
    ret = ''
    for i in range(0,6):
        ret += '%.2x' % ord(data[i])
        if i != 5:ret+=':'
    return ret

def __getProtocol(data):
    type = ''
    if data[0:2] == '\x08\x00' : type = 'ip'
    elif data[0:2] == '\x08\x06' : type = 'arp'
    elif data[0:2] == '\x80\x35' : type = 'revarp'
    elif data[0:2] == '\x81\x00' : type = 'vlan'
    elif data[0:2] == '\x86\xdd' : type = 'ipv6'
    else :type = 'Unknown'
    return type

def __decode_eth(data):
    dst = ''
    src = ''
    type = ''
    dst = __strfmac(data)
    data = data[6:]
    src = __strfmac(data)
    data = data[6:]
    type = __getProtocol(data)
    data = data[2:]
    return dst,src,type,data

def __decode_ip(s):  
    d={}
    d['order'] = ['version','header_len','dsfield','total_len','id','flags','fragment_offset','time to live','protocol','checksum','src_address','dst_address','options','data']
    d['version'] = ((ord(s[0]) & 0xf0) >> 4)
    d['header_len'] = (ord(s[0]) & 0x0f) * 4;
    d['dsfield']= ord(s[1])
    d['total_len']= socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']= '0x%.4X' % socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']= '0x%.2X' % ((ord(s[6]) & 0xe0) >> 5)
    d['fragment_offset']= '%d' % socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['time to live']= '%d' % ord(s[8])
    try:
        d['protocol']= ip_protocols[ord(s[9])]
    except:
        d['protocol']= 'Unknown'
        
    d['checksum']= '0x%.4X' % socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['src_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['dst_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>20:
        d['options']=s[20:d['header_len']]
    else:
        d['options']=None
    d['data']=s[d['header_len']:]

    return d


def __decode_arp(s):  
    d = {}
    d['order'] = ['hardware type','protocol','hardware size','protocol size','opcode','sender mac address','sender ip address','target mac address','target ip address']
    d['hardware type'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[0:2])[0])
    d['protocol'] = protocols[s[2:4]]
    d['hardware size'] = ord(s[4])
    d['protocol size'] = ord(s[5])
    d['opcode'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[6:8])[0])
    d['sender mac address'] =  __strfmac(s[8:])
    d['sender ip address'] = pcap.ntoa(struct.unpack('i',s[14:18])[0])
    d['target mac address'] = __strfmac(s[18:])
    d['target ip address'] = pcap.ntoa(struct.unpack('i',s[24:28])[0])
    return d

def __decode_ipv6(s):
    d = {}
    d['order'] = ['data']
    d['data'] = s
    return d

def parse(lenth, data, timest):
    if not hasattr(parse,'count'):
        parse.count = 1
    pkt = Pkt(lenth, data, timest)
    pkt.mac_dst, pkt.mac_src, type, data = __decode_eth(data)
    pkt.src = pkt.mac_src
    pkt.dst = pkt.mac_dst
    pkt.id = parse.count
    parse.count += 1
    pkt.dict['order'].append(type)
    pkt.data_len = lenth - 14
    if type == 'ip' : __parse_ip(pkt, data)
    if type == 'arp': __parse_arp(pkt, data)
    if type == 'ipv6' : __parse_ipv6(pkt, data)
#    pkt.data_len = 14
#    for t in pkt.dict['order']:
#        if i != 'Unknown' and i != 'arp':
#            pkt.data_len += pkt.dict[t]['header_len']
            
    return pkt

def clearcount():
    if hasattr(parse,'count'):
        parse.count = 1
        
def __parse_ip(pkt,data):    
    d = {'ip' : __decode_ip(data)}
    ip_type = d['ip']['protocol']
    pkt.src = d['ip']['src_address']
    pkt.dst = d['ip']['dst_address']
    pkt.dict['order'].append(ip_type)
    pkt.data_len -= d['ip']['header_len']
    if ip_type == 'TCP': d[ip_type] = __parse_ip_tcp(pkt,d['ip']['data'])
    elif ip_type == 'UDP': d[ip_type] = __parse_ip_udp(pkt,d['ip']['data'])
    elif ip_type == 'ICMP': d[ip_type] = __parse_ip_icmp(pkt,d['ip']['data'])
    else :return

    pkt.dict.update(d)
    
def __parse_arp(pkt,data):    
    d = {'arp' : __decode_arp(data)}
    pkt.dict.update(d)
    pkt.data_len = 0
    
def __parse_ipv6(pkt, data):
    d = {'ipv6' : __decode_ipv6(data)}
    pkt.dict.update(d)
    
def __parse_ip_tcp(pkt,s):
    d = {}
    d['order'] = ['src_port','dst_port','seq number','ack number','header_len','flags','window size','checksum','options','data']
    d['src_port'] = socket.ntohs(struct.unpack('H',s[0:2])[0])
    d['dst_port'] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['seq_number'] = (struct.unpack('I',s[4:8])[0])
    d['ack_number'] = (struct.unpack('I',s[8:12])[0])
    d['header_len'] = (ord(s[12]) & 0xf0) * 4;
    pkt.data_len -= d['header_len']
    
    d['flags']= '0x%.2X [%s]' % ( ord(s[13]), ','.join(decode_flag(ord(s[13]))) )
    d['window size'] = socket.ntohs(struct.unpack('H',s[14:16])[0]) * 128
    d['checksum'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[16:18])[0])
    if d['header_len']>20:
        if d['header_len'] == 32:
            d['options']=decode_options12(s[20:d['header_len']])
        if d['header_len'] == 40:
            d['options']=decode_options20(s[20:d['header_len']])
    else:
        d['options']=None
    d['data']=s[d['header_len']:]
    return d

def __parse_ip_udp(pkt,s):
    d = {}
    d['order'] = ['src_port','dst_port','length','checksum','data']
    d['src_port'] = socket.ntohs(struct.unpack('H',s[0:2])[0])
    d['dst_port'] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['length'] = socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['checksum'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[6:8])[0])
    d['header_len'] = 8
    pkt.data_len -= d['header_len']
    d['data'] = s[8:]
    return d

def __parse_ip_icmp(pkt,s):
    d = {}
    d['order'] = ['type','code','checksum','id','seq number','data']
    d['type'] = ord(s[0])
    d['code'] = ord(s[1])
    d['checksum'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['seq number'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[6:8])[0])
    d['header_len'] = 8
    pkt.data_len -= d['header_len']
    d['data'] = s[8:]
    return d


def decode_option12(s):
    d = {}
    ret = ''
    d['order'] = ['timestamp']
    if s[0:4] == '\x01\x01\x08\x0a':
        d['timestamp'] = decode_timestamp(s[2:])
    return d

def decode_option20(s):
    d = {}
    ret = ''
    d['order'] = ['MSS','timestamp']
    if s[0:2] == '\x02\x04':
        d['MSS'] =  struct.unpack('H',s[2:4])[0]
        d['timestamp'] = decode_timestamp(s[6:])
    return d
   
def decode_timestamp(s):
    if s[0:2] == '\x08\x0a':
        return 'TSval %d,TSecr %d' % ((struct.unpack('I',s[2:6])[0]),(struct.unpack('I',s[6:10])[0]))
    else:
        return ''
    
if __name__ == '__main__':
    open('eth0')
    