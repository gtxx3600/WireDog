#!/usr/bin/env python

from pkt import *

import socket
import struct
import pcap
import gzip
import StringIO
from tool import *
PROMPT = '[CLICK TO VIEW]'
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
out_of_order = []

class Pkt:
    def __init__(self, len, data, timest):
        self.timestamp = timest
        self.pkt_len = len
        self.data = data
        self.dict = {}
        self.dict['order'] = []
    
    def dump(self):
        print '\nDUMP OF Pkt'
        print 'pkt_id: %s' % self.id
        print 'pkt_len:',self.pkt_len
        print self.dict
        print 'END OF Pkt'
        

class Reassemble:
    def __init__(self,pkt,dict):
        self.seq = dict['seq_number']
        data = dict['data'][1]
        self.title_offset = data.find('\x0d\x0a') 
        self.title = data[:self.title_offset]
        self.header_offset = data.find('\x0d\x0a\x0d\x0a')
        self.header = data[self.title_offset + 2:self.header_offset + 4]
        self.prefix_len = self.header_offset + 4
        
        self.data_list = [(pkt,data)]
        options = self.header.split('\x0d\x0a')
        self.options = {'order':['HTTP']}
        self.options['HTTP'] = self.title
        self.total_length = self.prefix_len
        self.content_encoding = 'unknown'
        for i in options:
            name_val = i.split(': ')
            if len(name_val) != 2:
                continue
            name, val = name_val
            self.options['order'].append(name)
            self.options[name] = val
            if name == 'Content-Length':
                self.total_length += int(val)
            elif name == 'Content-Encoding':
                self.content_encoding = val 
        self.received_len = len(data)
        self.next_seq = self.seq + len(data)
        self.check()
        
    def isFinish(self):
        return self.total_length == self.received_len       
    
    def addpkt(self,pkt,dict):
        seq = dict['seq_number']
        data = dict['data'][1]
        if self.next_seq != seq and seq - self.next_seq != 1:
            print 'Error seq_number not continuous ! seq : %s ; next_seq : %s' % (seq,self.next_seq)
            pkt.dump()
        self.seq = seq
        self.next_seq = seq + len(data)
        self.data_list.append((pkt,data))
        self.received_len += len(data)
        self.check()
        
    def check(self):
        if self.isFinish():
            lastp,lastd = self.data_list[-1]
            data = ''
            r_dict = {'order':[]}
            for t in self.data_list:
                p, d = t
                if p == lastp:break
                r_dict['order'].append('packet %d'%p.id)
                r_dict['packet %d'%p.id] = '%d bytes' % len(d)
                data += d
                p.dict['order'].append('[TCP segment of a reassembled PDU]')
                p.dict['[TCP segment of a reassembled PDU]'] = 'Reassembled PDU in packet %s' % lastp.id
            
            r_dict['order'].append('packet %d'%lastp.id)
            r_dict['packet %d'%lastp.id] = '%d bytes' % len(lastd)
            data += lastd
            
                
            lastp.dict['order'].append('[Reassembled TCP Segments]')
            lastp.dict['[Reassembled TCP Segments]'] = r_dict
            lastp.dict['order'].append('HTTP')    
            self.options['order'].append('data')
            self.options['data'] = ('%d bytes %s' % (len(data),PROMPT),data)
            self.options['info'] = self.title
            if self.content_encoding != 'unknown':
                stm = StringIO.StringIO(data[self.header_offset + 4:])
                gzp = gzip.GzipFile(fileobj = stm)
                decompressed_data = gzp.read()
                self.options['order'].append('data_decompressed')
                self.options['data_decompressed'] = ('%d bytes %s' % (len(decompressed_data),PROMPT),decompressed_data)
            lastp.dict['HTTP'] = self.options
    
    def decompress(self,data):
        if self.content_encoding == 'gzip':
            try:
                ret = zlib.decompress(data)
                return ret
            except:
                return data
            
    def dump(self):
        print 'seq = ',self.seq
        print 'total_len = ',self.total_length
        print 'received_len = ',self.received_len
        print 'options = ',self.options
        print 'data_list = ',self.data_list
        for i in self.data_list:
            i[o].dump()
#class R_number:
#    def __init__(self,ip_addr,seq,ack):
#        self.seq_base = seq
#        self.ack_base = ack
#        self.next_seq = seq
#        self.acked = 0
#        self.seq = seq
#        self.ack = ack
#        self.ip = ip_addr
#        self.data_list = []
#        
#    def get_seq(self):
#        return self.seq - self.seq_base
#    
#    def get_ack(self):
#        return self.ack - self.ack_base
#    
#    def get_next_seq(self):
#        return self.next_seq - self.seq_base
#    
#    def dump(self):
#        print '\nDUMP OF R_number'
#        print 'ip : %s' % self.ip
#        print 'seq_base %s ; ack_base %s' % (self.seq_base,self.ack_base)
#        print 'seq %s ;ack %s ' %(self.seq,self.ack)
#        print 'R_seq %s ;R_ack %s ' %(self.get_seq(),self.get_ack())
#        print 'next_seq %s' % self.next_seq
#        print 'R_next_seq %s' % self.get_next_seq()
#        print 'data_list :' ,self.data_list
#        print 'END OF R_number\n'
                                                  
#class PoolEntry:
#    'PoolEntry(pkt,dict,key,flags)'
#    def __init__(self,pkt,dict,key,flags):
#    
#        self.A = R_number(pkt.dict['ip']['src_address'] + ':' + str(dict['src_port']),0,0)
#        self.B = R_number(pkt.dict['ip']['dst_address'] + ':' + str(dict['dst_port']),0,0)
#        self.C = self.A
#        self.D = self.B
#
#        self.mss = 65535
#        self.key = key
#        self.out_of_order = []
#        self.reassemble = False
#        self.pkts = []
#        
#        self.addpkt(pkt,dict,flags)
#        
#    def set_mss(self,mss):
#        if self.mss > mss:
#            self.mss = mss
#    def syn(self,pkt,d):
#        seq = d['seq_number']
#            
#        self.C.seq_base = seq
#        self.C.seq = seq
#        self.C.next_seq = seq 
#        self.D.ack_base = seq
#        
#    def ack(self,pkt,d):
#        ack = d['ack_number']       
#        
#        self.C.ack = ack
#        self.D.acked = ack - 1
#        if self.D.next_seq != ack : 
#            print 'Not match of ack and next_seq : ack %s ; next_seq %s ' % (ack,self.D.next_seq)
#        
#        
#    def synack(self,pkt,dict):
#        seq = dict['seq_number']
#        ack = dict['ack_number']
#        try:
#            mss = d['options']['MSS']
#        except:
#            mss = 65535
#        data = dict['data']
#        header_len = dict['header_len']
#        if pkt.dict['ip']['src_address'] == self.A.ip :
#            c = self.A
#            d = self.B
#        else:
#            c = self.B
#            d = self.A
#        self.set_mss(mss)
#        c.seq_base = seq
#        c.seq = seq
#        c.ack = ack
#        d.ack_base = seq
#        d.seq_next = ack
#        self.addpkt(pkt, seq, ack, data, header_len)
#        
#        
#    def process_out_of_order(self,d):
#        pass
#    def process_data(self,pkt,data,header_len):
#        if len(data) < self.mss - header_len + 20 :
#            if self.reassemble and self.C.data_list:
#                self.C.data_list.append((pkt.id,data))
#                final = ''
#                id_list = []
#                for data_seg in self.C.data_list:
#                    id, part = data_seg
#                    id_list.append(id)
#                    final += part
#                    
#                self.C.data_list = []
#                pkt.dict['order'].append('Reassembled_data')
#                pkt.dict['Reassembled_data'] = {
#                                                'order':['pkt_list','data'],
#                                                'pkt_list':id_list,
#                                                'data':final
#                                                }
#                self.reassemble = False
#                                    
#        elif len(data) == self.mss - header_len + 20 :
#            if not self.reassemble : self.reassemble = True
#            self.C.data_list.append((pkt.id,data))
#            pkt.dict['order'].append('Part_of_reassembled_data')
#            pkt.dict['Part_of_reassembled_data'] = {
#                                                    'order':['data'],
#                                                    'data':data
#                                                    }
#            
#        else:
#            print 'ERROR:Data_len surpass MSS ' ,pkt.dict
#            return
#
#    def process_pkt(self,pkt,d):
#
#        data = d['data']
#        header_len = d['header_len']
#        data_len = len(data)
#        seq = d['seq_number']
#
#        if seq > self.C.next_seq :
#            print 'seq :%s > next_seq : %s put in outoforder' % (seq,self.C.next_seq)
#            self.out_of_order.append((pkt,d))
#            return 1
#        elif seq == self.C.next_seq :
#            self.C.seq = seq
#            self.C.next_seq = seq + data_len
#            self.pkts.append(pkt)
#            self.process_data(pkt, data, header_len)
#            return 0
#        else:
#            print 'Retransmit packet or error'
#            print 'seq %s ; ' % seq
#            print 'next_seq : %s' %self.C.next_seq
#            print pkt.dict
#            return 1    
#
#    def addpkt(self,pkt,d,flags):
#        
#        if pkt.dict['ip']['src_address'] + ':' + str(d['src_port']) == self.A.ip :
#            self.C = self.A
#            self.D = self.B
#        elif pkt.dict['ip']['src_address'] + ':' + str(d['src_port']) == self.B.ip :
#            self.C = self.B
#            self.D = self.A
#        else:
#            for i in range(0,100):
#                print 'Fatel error!!'   
#            self.C = self.A
#            self.D = self.B
#        
#        try:
#            mss = d['options']['MSS']
#            self.set_mss(mss)
#        except:
#            print 'No MSS'
#        
#        data = d['data']
#        header_len = d['header_len']
#        
#        if 'SYN' in flags:
#            self.syn(pkt, d)
#            
#        ret = self.process_pkt(pkt,d)
#        if 'SYN' in flags:
#            self.C.next_seq += 1
#        if 'ACK' in flags:
#            self.ack(pkt, d)
#    
##    def addpkt(self,pkt,seq,ack,data,header_len):
##        if pkt.dict['ip']['src_address'] == self.A.ip :
##            c = self.A
##            d = self.B
##        else:
##            c = self.B
##            d = self.A
##        if seq > c.next_seq:
##            print 'seq :%s > next_seq : %s put in outoforder' % (seq,c.next_seq)
##            self.out_of_order.append((pkt,seq,ack,data,header_len))
##            return
##        elif seq == c.next_seq:
##            c.seq = seq
##            c.ack = ack
##            if not d.next_seq == ack:
##                print 'next_seq not match ack'
##                print d.next_seq,ack
##                d.next_seq = ack
##            c.next_seq = c.seq + len(data)
##            
##            self.pkts.append(pkt)
##            
##            if len(data) < self.mss - header_len + 20 :
##                if self.reassemble:
##                    self.data_list.append((pkt.id,data))
##                    final = ''
##                    id_list = []
##                    for data_seg in self.data_list:
##                        id, part = data_seg
##                        id_list.append(id)
##                        final += part
##                        
##                    self.data_list = []
##                    pkt.dict['order'].append('Reassembled_data')
##                    pkt.dict['Reassembled_data'] = {
##                                                    'order':['pkt_list','data'],
##                                                    'pkt_list':id_list,
##                                                    'data':final
##                                                    }
##                    self.reassemble = False
##                                        
##            elif len(data) == self.mss - header_len + 20 :
##                if not self.reassemble : self.reassemble = True
##                self.data_list.append((pkt.id,data))
##                pkt.dict['order'].append('Part_of_reassembled_data')
##                pkt.dict['Part_of_reassembled_data'] = {
##                                                        'order':['data'],
##                                                        'data':data
##                                                        }
##                
##            else:
##                print 'ERROR:Data_len surpass MSS ' ,pkt.dict
##                return
##            
##            if self.out_of_order:
##                for i in self.out_of_order:
##                    if i[1] == c.next_seq:
##                        opkt,oseq,oack,odata,oheader_len = i
##                        self.out_of_order.remove(i)
##                        self.addpkt(opkt,oseq,oack,odata,oheader_len)
##                        break
##                    
##        else:
##            print 'Retransmit packet or error'
##            print 'seq %s ; ack %s ;' %(seq,ack)
##            print 'next_seq : %s' %c.next_seq
##            pkt.dict
##            
##            return 
#    def dump(self):
#        print '\nDUMP OF PoolEntry'
#        print 'key : ',self.key
#        print 'MSS',self.mss
#        print 'Reassembling: ' ,self.reassemble
#        print 'out_of_order',self.out_of_order
#        for i in self.out_of_order:
#            i[0].dump()
#        self.C.dump()
#        self.D.dump()
#        print 'END OF PoolEntry\n'

def __keygen(src_ip,src_port,dst_ip,dst_port):
#    if src_ip + '%d' % src_port > dst_ip + '%d' % dst_port :
    return src_ip + ':%d' % src_port + '|' + dst_ip + ':%d' % dst_port
#    else:
#        return dst_ip + ':%d' % dst_port + '|' + src_ip + ':%d' % src_port      
        
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
    d['order'] = ['version','header_len','dsfield','total_len','id','flags','fragment_offset','time_to_live','protocol','checksum','src_address','dst_address','options','data']
    d['version'] = ((ord(s[0]) & 0xf0) >> 4)
    d['header_len'] = (ord(s[0]) & 0x0f) * 4;
    d['dsfield']= ord(s[1])
    d['total_len']= socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']= '0x%.4X' % socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']= '0x%.2X' % ((ord(s[6]) & 0xe0) >> 5)
    d['fragment_offset']= '%d' % socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['time_to_live']= '%d' % ord(s[8])
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
    d['data']=('%d bytes %s' % (len(s[d['header_len']:]),PROMPT),s[d['header_len']:])

    return d


def __decode_arp(s):  
    d = {}
    d['order'] = ['hardware type','protocol','hardware_size','protocol_size','opcode','src_mac','src_address','dst_mac','dst_address']
    d['hardware type'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[0:2])[0])
    d['protocol'] = protocols[s[2:4]]
    d['hardware_size'] = ord(s[4])
    d['protocol_size'] = ord(s[5])
    d['opcode'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[6:8])[0])
    d['src_mac'] =  __strfmac(s[8:])
    d['src_address'] = pcap.ntoa(struct.unpack('i',s[14:18])[0])
    d['dst_mac'] = __strfmac(s[18:])
    d['dst_address'] = pcap.ntoa(struct.unpack('i',s[24:28])[0])
    d['info'] = 'Who has %s ? Tell %s' % (d['dst_address'],d['src_address'])
    return d

def __decode_ipv6(s):
    d = {}
    d['order'] = ['data']
    d['data'] = ('%d bytes %s' % (len(s),PROMPT),s)
    d['info'] = ''
    return d

def __infogen(pkt):
    i = -1
    while True:
        if pkt.dict['order'][i].startswith('['):
            i -= 1
        else:
            break
    try:
        pkt.info = pkt.dict[pkt.dict['order'][i]]['info']
    except:
        pkt.info = ''

        
def parse(lenth, data, timest):
    if not hasattr(parse,'count'):
        parse.count = 1
    pkt = Pkt(lenth, data, timest)
    pkt.mac_dst, pkt.mac_src, type, data = __decode_eth(data)
    pkt.src = pkt.mac_src
    pkt.dst = pkt.mac_dst
    pkt.id = parse.count
    parse.count += 1
    pkt.dict['order'].append('Ethernet')
    pkt.dict['Ethernet'] = {'order':['src_mac','dst_mac','protocol'],
                            'src_mac':pkt.src,
                            'dst_mac':pkt.dst,
                            'protocol':type,
                            'info':''
                            }
    pkt.dict['order'].append(type)
    pkt.data_len = lenth - 14
    
    if type == 'ip' : __parse_ip(pkt, data)
    if type == 'arp': __parse_arp(pkt, data)
    if type == 'ipv6' : __parse_ipv6(pkt, data)
#    pkt.data_len = 14
#    for t in pkt.dict['order']:
#        if i != 'Unknown' and i != 'arp':
#            pkt.data_len += pkt.dict[t]['header_len']
    __infogen(pkt)
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
    pkt.dict.update(d)
    if ip_type == 'TCP': d[ip_type] = __parse_ip_tcp(pkt,d['ip']['data'][1])
    elif ip_type == 'UDP': d[ip_type] = __parse_ip_udp(pkt,d['ip']['data'][1])
    elif ip_type == 'ICMP': d[ip_type] = __parse_ip_icmp(pkt,d['ip']['data'][1])
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
    d['order'] = ['src_port','dst_port','seq_number','ack_number','header_len','flags','window_size','checksum','options','data']
    d['src_port'] = socket.ntohs(struct.unpack('H',s[0:2])[0])
    d['dst_port'] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['seq_number'] = (struct.unpack('!I',s[4:8])[0])
    d['ack_number'] = (struct.unpack('!I',s[8:12])[0])
    d['header_len'] = ((ord(s[12]) & 0xf0)>>4) * 4;
    pkt.data_len -= d['header_len']
    flags = decode_flag(ord(s[13]))
    d['flags']= '0x%.2X [%s]' % ( ord(s[13]), ','.join(flags) )
    d['window_size'] = socket.ntohs(struct.unpack('H',s[14:16])[0]) * 128
    d['checksum'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[16:18])[0])
    d['options']=decode_option_tcp(s[20:d['header_len']])
    d['data']=('%d bytes %s' % (len(s[d['header_len']:]), PROMPT), s[d['header_len']:])
    d['info'] = '%s > %s [%s] Seq = %d Len = %d' %(d['src_port'],d['dst_port'],','.join(flags),d['seq_number'],len(d['data'][1]))
    ip = pkt.dict['ip']
    key = __keygen(ip['src_address'],d['src_port'],ip['dst_address'],d['dst_port'])
    pkt.dict.update({'TCP':d})
    if d['data'][1].startswith('HTTP'):
        if stream_pool.has_key(key):
            print "Duplicate stream_pool_key %s" % key
        r = Reassemble(pkt,d)
        if not r.isFinish():
            stream_pool[key] = r
    elif d['data'][1].startswith('GET'):
        if stream_pool.has_key(key):
            print "Duplicate stream_pool_key %s" % key
        r = Reassemble(pkt,d)
        if not r.isFinish():
            stream_pool[key] = r
    else:
        if stream_pool.has_key(key):
            stream_pool[key].addpkt(pkt,d)
            if stream_pool[key].isFinish():
                stream_pool.pop(key)
#    if 'SYN' in flags and not 'ACK' in flags:
#        if stream_pool.has_key(key):
#            print "Duplicate stream_pool_key %s" % key
#            print stream_pool
#            return {'order':[]}
#        stream_pool[key] = PoolEntry(pkt,d,key,flags)
##    elif 'SYN' in flags and 'ACK' in flags:
##        if not stream_pool.has_key(key):
##            print "Lack of stream_pool_key %s" % key
##            print stream_pool
##            stream_pool[key] = PoolEntry(pkt,d,key)
##            return {'order':[]}
##        stream_pool[key].addpkt(pkt,d['seq_number'],d['ack_number'],d['data'],d['header_len'])
##        stream_pool[key].synack(pkt,d)
#    else:
#        if not stream_pool.has_key(key):
#            print "Lack of stream_pool_key %s" % key
#            print stream_pool
#            stream_pool[key] = PoolEntry(pkt,d,key,flags)
#            #return {'order':[]}
#        else:
#            stream_pool[key].addpkt(pkt,d,flags)
#    stream_pool[key].dump()
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
    d['data'] = ('%d bytes %s' % (len(s[8:]),PROMPT),s[8:])
    d['info'] = 'Src port: %d Dst port: %d Len = %d' % (d['src_port'],d['dst_port'],len(d['data'][1]))
    
    return d

def __parse_ip_icmp(pkt,s):
    type = {0:'Echo Reply',
            8:'Echo Request',
            3:'Dst Unreachable',
            4:'Source Quench',
            5:'Redirect',
            11:'Time Exceeded',
            12:'Parameter Problem',
            13:'Timestamp Request',
            14:'Timestamp Reply',
            15:'Infomation Request',
            16:'Infomation Reply',
            17:'Address Mask Request',
            18:'Address Mask Reply'
            }
    code = {
            0:'Network Unreachable',
            1:'Host Unreachable',
            2:'Protocol Unreachable',
            3:'Port Unreachable',
            4:'Fragment Needed and DF set',
            5:'Source Route Failed',
            6:'Destination network unknown',
            7:'Destination host unknown',
            8:'Source host isolated'
            }
    d = {}
    d['order'] = ['type','code','checksum','id','seq_number','data']
    d['type'] = ord(s[0])
    d['code'] = ord(s[1])
    d['checksum'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['seq_number'] = '0x%.4X' % socket.ntohs(struct.unpack('H',s[6:8])[0])
    d['header_len'] = 8
    pkt.data_len -= d['header_len']
    d['data'] = ('%d bytes %s' % (len(s[8:]),PROMPT),s[8:])
    try:
        d['info'] = type[d['type']]
        if d['type'] == 3:
            d['info'] += ' (%s)' % code[d['code']] 
    except:
        if not d['info']:
            d['info'] = 'Unknown'
    return d

def decode_option_tcp(s):
    d = {}
    s_bak = s
    d['order'] = []
    while s:
        if s[0] == '\x01':
            s = s[1:]
        elif s[0] == '\x02':
            s = s[1:]
            if s[0] == '\x04':
                s = s[1:]
                d['MSS'] =  struct.unpack('!H',s[0:2])[0]
                d['order'].append('MSS')
                s = s[2:]
            else:
                print 'Decode_option: unknown situation 02%.2X' % ord(s[0])
                print map(ord,s_bak)
                s = s[1:]
        elif s[0] == '\x03':
            s = s[1:]
            if s[0] == '\x03':
                d['Window_scale'] = ord(s[1])
                d['order'].append('Window_scale')
                s = s[2:]
            else:
                print 'Decode_option: unknown situation 03%.2X' % ord(s[0])
                print map(ord,s_bak)
                s = s[1:]
        elif s[0] == '\x04':
            s = s[1:]
            if s[0] == '\x02':
                d['SACK'] = 'permitted'
                d['order'].append('SACK')
                s = s[1:]
            else:
                print 'Decode_option: unknown situation 04%.2X' % ord(s[0])
                print map(ord,s_bak)
                s = s[1:]
        elif s[0] == '\x05':
            s = s[1:]
            if s[0] == '\x0a':
                s = s[1:]
                d['SACK'] = {
                             'order':['left edge','right edge'],
                             'left edge':'0x%.8X' % struct.unpack('!H',s[0:4])[0],
                             'right edge': '0x%.8X' % struct.unpack('!H',s[4:8])[0]
                             }
                d['order'].append('SACK')
                s = s[8:]
                print 'add sack'
            else:
                print 'Decode_option: unknown situation 08%.2X' % ord(s[0])
                print map(ord,s_bak)
                s = s[1:]
        elif s[0] == '\x08':
            s = s[1:]
            if s[0] == '\x0a':
                s = s[1:]
                d['timestamp'] = 'TSval %d,TSecr %d' % ((struct.unpack('!I',s[0:4])[0]),(struct.unpack('!I',s[4:8])[0]))
                d['order'].append('timestamp')
                s = s[8:]
            else:
                print 'Decode_option: unknown situation 08%.2X' % ord(s[0])
                print map(ord,s_bak)
                s = s[1:]
        else:
            print 'Decode_option: unknown situation %.2X' % ord(s[0])
            print map(ord,s_bak)
            s = s[1:]
    return d
    
#def decode_option12(s):
#    d = {}
#    ret = ''
#    d['order'] = ['timestamp']
#    if s[0:4] == '\x01\x01\x08\x0a':
#        d['timestamp'] = decode_timestamp(s[2:])
#    return d
#
#def decode_option20(s):
#    d = {}
#    ret = ''
#    d['order'] = ['MSS','timestamp']
#    if s[0:2] == '\x02\x04':
#        d['MSS'] =  struct.unpack('H',s[2:4])[0]
#        d['timestamp'] = decode_timestamp(s[6:])
#    return d
#   
#def decode_timestamp(s):
#    if s[0:2] == '\x08\x0a':
#        return 'TSval %d,TSecr  %d' % ((struct.unpack('I',s[2:6])[0]),(struct.unpack('I',s[6:10])[0]))
#    else:
#        return ''
#    
if __name__ == '__main__':
    open_live('eth0')
    