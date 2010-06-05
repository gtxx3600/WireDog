#!/usr/bin/env python

import pcap

p =pcap.pcapObject()

def open(eth):
    p.open_live(eth, 65535, 0, -1)

def close():
    p.open_dead(0,1024)

def setblock():
    p.setnonblock(False)

def next():
    return p.next()

def stats():
    return p.stats()

def filter(cmd):
    p.setfilter(cmd,0,0xffffffff)

def dispatch(count,callback):
    if not callable(callback):
        print 'callback must be callable'
        return 
    if not count >= 0:
        print 'count must beyond zero'
        return
    p.dispatch(count,callback)
    
def findalldevs():
    return pcap.findalldevs()