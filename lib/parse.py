
from pkt import *
import time
import socket
import pcap

protocols={socket.IPPROTO_TCP:'TCP',
           socket.IPPROTO_UDP:'UDP',
           socket.IPPROTO_ICMP:'ICMP'}

class Pkt:
    def __init__(self, len, data, timest):
        self.timestamp = timest
        self.pkt_len = len
        self.data = data
        self.dict = {}
        
def __strfmac(data):
    ret = ''
    for i in range(0,6):
        ret += '%.2x' % ord(data[i])
        if i != 6:ret+=':'
    data = data[6:]
    return ret, data

def __getProtocol(data):
    type = ''
    if data[0:2] == '\x08\x00' : type = 'ip'
    if data[0:2] == '\x08\x06' : type = 'arp'
    if data[0:2] == '\x80\x35' : type = 'revarp'
    if data[0:2] == '\x81\x00' : type = 'vlan'
    if data[0:2] == '\x86\xdd' : type = 'ipv6'
    return type, data[2:]

def __decode_eth(data):
    dst = ''
    src = ''
    type = ''
    dst, data = __strfmac(data)
    src, data = __strfmac(data)
    type, data = __getProtocol(data)
    return dst,src,type,data[6+6+2]

def __decode_ip(s):  
    d={}
    d['order'] = ['version','header_len','dsfield','total_len','id','flags','fragment_offset','time to live','protocol','checksum','src_address','dst_address','options','data']
    d['version'] = ((ord(s[0]) & 0xf0) >> 4)
    d['header_len'] = (ord(s[0]) & 0x0f) * 4;
    d['dsfield']= ord(s[1])
    d['total_len']= socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']= '0x%.4x' % socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']= '0x%.2x' % (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']= '%d' % socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['time to live']= '%d' % ord(s[8])
    d['protocol']= protocols[ord(s[9])]
    d['checksum']= '0x%.4x' % socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['src_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['dst_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>20:
      d['options']=s[20:d['header_len']]
    else:
      d['options']=None
    d['data']=s[d['header_len']:]
    return d


def __decode_arp(data):  
    dict = {}
    return dict

def parse(*args):
    if len(args)!= 3 : return None
    len, data, timest = args
    pkt = Pkt(len, data, timest)
    pkt.type = []
    pkt.mac_dst, pkt.mac_src, type, data = __decode_eth(data)
    pkt.type.append(type)
    if type == 'ip' : __parse_ip(pkt, data)
    if type == 'arp': __parse_arp(pkt, data)
    
    return pkt

def __parse_ip(pkt,data):    
    d = {'ip' : __decode_ip(data)}
    ip_type = d['ip']['protocol']
    pkt.type.append(ip_type)
    if ip_type == 'TCP': d[ip_type] = __parse_ip_tcp(d['ip']['data'])
    if ip_type == 'UDP': d[ip_type] = __parse_ip_udp(d['ip']['data'])
    if ip_type == 'ICMP': d[ip_type] = __parse_ip_icmp(d['ip']['data'])
    pkt.dict.update(d)
    
def __parse_arp(pkt,data):    
    d = {'arp' : __decode_arp(data)}
    pkt.type.append(d['arp']['type'])
    pkt.dict.update(d)
    
def __parse_ip_tcp(s):
    d = {}
    d['order'] = ['src_port','dst_port','seq number','ack number','header_len','flags','window size','checksum','options','data']
    d['src_port'] = socket.ntohs(struct.unpack('H',s[0:2])[0])
    d['dst_port'] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['seq number'] = socket.ntohs(struct.unpack('i',s[4:8])[0])
    d['ack number'] = socket.ntohs(struct.unpack('i',s[8:12])[0])
    d['header_len'] = (ord(s[12]) & 0xf0) * 4;
    d['flags']= '0x%.2x' % ord(s[13])
    d['window size'] = socket.ntohs(struct.unpack('H',s[14:16])[0]) * 128
    d['checksum'] = '0x%.4x' % socket.ntohs(struct.unpack('H',s[16:18])[0])
    if d['header_len']>20:
      d['options']=s[20:d['header_len']]
    else:
      d['options']=None
    d['data']=s[d['header_len']:]
    return d

def __parse_ip_udp(data):
    d = {}
    return d

def __parse_ip_icmp(data):
    d = {}
    return d
