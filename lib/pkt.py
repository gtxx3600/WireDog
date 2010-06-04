import pcap

p =pcap.pcapObject()


def open(eth):
    p.open_live(eth, 65535, 0, -1)

def close():
    p.open_dead(0,1024)

def next():
    return p.next() 
    pass

def stats():
    return p.stats()

def filter(cmd):
    p.setfilter(cmd,0,0xffffffff)
    