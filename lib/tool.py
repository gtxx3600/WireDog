#!/usr/bin/env python

import re

def search_in_pkts(s,pkts):
    'searchstring(s,pkts) return a dict, keys are instance of parse.Pkt, value is a tuple (global_index,data_index,string startswith s)'
    ret = {}
    for pkt in pkts:
        type = pkt.dict['order'][-1]
        if type == 'TCP' or type == 'UDP':
            d = pkt.dict[type]
            index = d['data'][1].find(s)
            if index >= 0 :
                global_index = index + 14 + pkt.dict['ip']['header_len'] + pkt.dict[type]['header_len'] 
                ret[pkt] = (global_index,index,d['data'][1][index:])
                
    return ret

def search_in_pkt(s,pkt):
    type = pkt.dict['order'][-1]
    if type == 'TCP' or type == 'UDP':
        d = pkt.dict[type]
        index = d['data'][1].find(s)
        if index >= 0 :
            global_index = index + 14 + pkt.dict['ip']['header_len'] + pkt.dict[type]['header_len'] 
            return (global_index,index,d['data'][1][index:])
                
    return ()

def decode_flag(flag):
    ret = []
    dict = { 1:'FIN',
             2:'SYN',
             4:'RST',
             8:'PSH',
             16:'ACK',
             32:'URG',
             64:'ECN',
             128:'CWR'}
    for i in range(0,8):
        if flag & (1 << i):
            ret.append(dict[1<<i])
    
    return ret

def search_string_parse(s):
    s = s.split('=', 1)
    s[0] = s[0].strip()
    s[1] = s[1].strip()
    if len(s) != 2 or \
            not(s[1].startswith('"') and s[1].endswith('"')):
        return None
    key = s[0]
    value = s[1][1:-1]
    key = key.lower()
    if key != 'data':
        value = value.upper()
    return (key, value)

def search_value(pkt, k, v):
    def __search_dict(d, k, v):
        if d.has_key(k) and type(d[k]) == str and d[k].upper() == v:
            return True
        for key in d.keys():
            if type(d[key]) == dict and __search_dict(d[key], k, v):
                return True
        return False
    return __search_dict(pkt.dict, k, v)

def search_key(pkt, k):
    def __search_dict(d, k):
        if d.has_key(k):
            return True
        for key in d.keys():
            if type(d[key]) == dict and __search_dict(d[key], k):
                return True
        return False
    return __search_dict(pkt.dict, k)

def search_data(pkt, v):
    if search_in_pkt(v, pkt):
        return True
    return False

search_map = {
              'src_ip' : lambda pkt, v : search_value(pkt, 'src_address', v),
              'dst_ip' : lambda pkt, v : search_value(pkt, 'dst_address', v),
              'ip' : lambda pkt, v : search_value(pkt, 'src_address', v) or search_value(pkt, 'dst_address', v),
              'src_port' : lambda pkt, v : search_value(pkt, 'src_port', v),
              'dst_port' : lambda pkt, v : search_value(pkt, 'dst_port', v),
              'port' : lambda pkt, v : search_value(pkt, 'src_port', v) or search_value(pkt, 'dst_port', v),
              'src_mac' : lambda pkt, v : search_value(pkt, 'src_mac', v),
              'dst_mac' : lambda pkt, v : search_value(pkt, 'dst_mac', v),
              'mac' : lambda pkt, v : search_value(pkt, 'src_mac', v) or search_value(pkt, 'dst_mac', v),
              'proto' : search_key,
              'data' : search_data,
              }

def s_check_single(s):
    if s == '':
        return True
    ret = search_string_parse(s)
    if ret == None:
        return False
    if not search_map.has_key(ret[0]):
        return False
    return True

def s_check(s):
    if s == '':
        return True
    pattern = r'([a-zA-Z_]+\s*=\s*".*")'
    subs = re.findall(pattern, s)
    for sub in subs:
        ret = s_check_single(sub)
        if not ret:
#            print sub
            return False
        s = s.replace(sub, 'True')
    try:
        eval(s)
        return True
    except:
        return False

def is_match_single(s, pkt):
    #proto ip mac port data
    ret = search_string_parse(s)
    if ret == None:
        return None
    key, value = ret
    if not search_map.has_key(key):
        return None
    return search_map[key](pkt, value)

def is_match(s, pkt):
    pattern = r'([a-zA-Z_]+\s*=\s*"[^"]*")'
    subs = re.findall(pattern, s)
    for sub in subs:
        ret = is_match_single(sub, pkt)
        s = s.replace(sub, str(ret))
    return eval(s)
