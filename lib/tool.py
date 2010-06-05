#!/usr/bin/env python

from parse import *


def searchstring(s,pkts):
    'searchstring(s,pkts) return a dict, keys are instance of parse.Pkt, value is a tuple (global_index,data_index,string startswith s)'
    ret = {}
    for pkt in pkts:
        if pkt.__class__ is Pkt:
            type = pkt.dict['order'][-1]
            if type == 'TCP' or type == 'UDP':
                d = pkt.dict[type]
                index = d['data'].find(s)
                if index >= 0 :
                    global_index = index + 14 + pkt.dict['ip']['header_len'] + pkt.dict[type]['header_len'] 
                    ret[pkt] = (global_index,index,d['data'][index:])
                
    return ret