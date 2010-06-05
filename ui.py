#!/usr/bin/env python

import gobject
import gtk
import pango
import threading
import time

from lib.parse import *
from lib.tool import *

class SniffThread(threading.Thread):
    def __init__(self, eth, disp_f, disp_s):
        threading.Thread.__init__(self, name='sniff')
        self.running = False
        self.disp_f = disp_f
        self.disp_s = disp_s
        self.eth = eth
        
    def show_pkt(self, *n):
        if not n[1]:
            return
        pkt = parse(*n)
        self.disp_f(pkt)
#        self.disp_s(stats())

    def run(self):
        open(self.eth)
        self.disp_s()
        while self.running:
            try:
                n = next()
                if n == None:
                    time.sleep(0.01)
                else:
                    self.show_pkt(*n)
            except KeyboardInterrupt:
                break
            except:
                import traceback
                import sys
                traceback.print_exc(file=sys.stderr)
        self.disp_s(stats())
        close()

class MainView:
    def __init__(self):
        self.sniffThread = None
        self.timebase = None
        self.eth = None
        self.search_string = ''
        self.filter_string = ''
        self.hided_pkts = []
        
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_size_request(800, 500)
        self.window.connect('delete-event', self.__quit)
        
        self.startbtn = startbtn = gtk.Button('start')
        startbtn.set_sensitive(False)
        startbtn.connect('clicked', self.__start)
        
        self.stopbtn = stopbtn = gtk.Button('stop')
        stopbtn.set_sensitive(False)
        stopbtn.connect('clicked', self.__stop)
        
        savebtn = gtk.Button('save')
        
        devlabel = gtk.Label('Select a interface: ')
        self.combobox = combobox = gtk.combo_box_new_text()
        devs = findalldevs()
        for dev in devs:
            if dev[0] != 'any':
                combobox.append_text(dev[0])
        combobox.connect('changed', self.__select_dev)
        
        toolbar = gtk.HBox(False, 10)
        toolbar.pack_start(startbtn, False)
        toolbar.pack_start(stopbtn, False)
        toolbar.pack_start(savebtn, False)
        toolbar.pack_end(combobox, False)
        toolbar.pack_end(devlabel, False)
        
        self.filterbtn = filterbtn = gtk.Button('filter')
        filterbtn.filterentry = filterentry = gtk.Entry()
        filterbtn.connect('clicked', self.__filter)
        
        filterbar = gtk.HBox()
        filterbar.pack_start(filterentry, True)
        filterbar.pack_start(filterbtn, False)
        
        searchbtn = gtk.Button('search')
        searchbtn.searchentry = searchentry = gtk.Entry()
        searchbtn.connect('clicked', self.__search)
        
        searchbar = gtk.HBox()
        searchbar.pack_start(searchentry, True)
        searchbar.pack_start(searchbtn, False)
        
        toolbar2 = gtk.HBox(False)
        toolbar2.pack_start(filterbar, True)
        toolbar2.pack_start(gtk.SeparatorToolItem(), False)
        toolbar2.pack_start(searchbar, True)
        
        self.pktlist = pktlist = gtk.TreeStore(
                                gobject.TYPE_BOOLEAN, 
                                gobject.TYPE_INT,
                                gobject.TYPE_STRING,
                                gobject.TYPE_STRING,
                                gobject.TYPE_STRING,
                                gobject.TYPE_STRING,
                                gobject.TYPE_PYOBJECT, 
                                )
        listview = gtk.TreeView(pktlist)
        listview.set_rules_hint(True)
        listview.get_selection().connect('changed', self.__select_row)
        
        column_heads = ['Save?', 'No.', 'Time', 'Source', 'Destination', 'Protocol']
        
        def __toggle_cell_func(column, cell, model, iter):
            b = model.get_value(iter, 0)
            cell.set_property('active', b)
            
        def __toggled(cellrenderertoggle, path, treestore):
            treestore[path][0] = not treestore[path][0]
            
        toggle_render = gtk.CellRendererToggle()
        toggle_render.set_property('activatable', True)
        toggle_render.connect('toggled', __toggled, pktlist)
        toggle_column = gtk.TreeViewColumn(column_heads[0])
        toggle_column.pack_start(toggle_render, False)
        toggle_column.set_cell_data_func(toggle_render, __toggle_cell_func)
        listview.append_column(toggle_column)
        
        def __text_cell_func(column, cell, model, iter, i):
            text = model.get_value(iter, i)
            cell.set_property('font-desc', pango.FontDescription('Monospace 10'))
            cell.set_property('text', text)
            
        for i in range(1, 6):
            __render = gtk.CellRendererText()
            __column = gtk.TreeViewColumn(column_heads[i])
            __column.pack_start(__render, False)
            __column.set_resizable(True)
            __column.set_sort_column_id(i)
            __column.set_cell_data_func(__render, __text_cell_func, i)
            listview.append_column(__column)
        
        listscroll = gtk.ScrolledWindow()
        listscroll.set_policy(gtk.POLICY_NEVER, gtk.POLICY_ALWAYS)
        listscroll.set_shadow_type(gtk.SHADOW_IN)
        listscroll.add(listview)
        
        listbox = gtk.HBox()
        listbox.pack_start(listscroll, True)
        
        self.treestore = treestore = gtk.TreeStore(
                                  gobject.TYPE_STRING, 
                                  gobject.TYPE_STRING,
                                  )
        
        treeview = gtk.TreeView(treestore)
        treeview.set_headers_visible(False)
        
        for i in range(0, 2):
            __render = gtk.CellRendererText()
            __column = gtk.TreeViewColumn()
            __column.pack_start(__render, False)
            __column.set_cell_data_func(__render, __text_cell_func, i)
            treeview.append_column(__column)
        
        treescroll = gtk.ScrolledWindow()
        treescroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        treescroll.set_shadow_type(gtk.SHADOW_IN)
        treescroll.add(treeview)
        
        treebox = gtk.HBox()
        treebox.pack_start(treescroll, True)
        
        self.textview = textview = gtk.TextView()
        textview.set_editable(False)
        textview.set_cursor_visible(False)
        textview.modify_font(pango.FontDescription('Monospace 10'))
        
        textscroll = gtk.ScrolledWindow()
        textscroll.set_policy(gtk.POLICY_NEVER, gtk.POLICY_ALWAYS)
        textscroll.set_shadow_type(gtk.SHADOW_IN)
        textscroll.add(textview)
        
        textbox = gtk.HBox()
        textbox.pack_start(textscroll)
        
        infobox = gtk.VBox(False, 5)
        
        paned1 = gtk.VPaned()
        paned2 = gtk.VPaned()
        
        paned1.pack1(listbox, True, False)
        paned1.pack2(paned2, True, False)
        paned2.pack1(treebox, True, False)
        paned2.pack2(textbox, True, False)
        
        infobox.pack_start(paned1, True)
        
        self.statsbar = statsbar = gtk.Label()
        self.show_stats()
        statsbox = gtk.HBox()
        statsbox.pack_start(statsbar, True)
        
        vbox = gtk.VBox()
        vbox.pack_start(toolbar, False)
        vbox.pack_start(toolbar2, False)
        vbox.pack_start(infobox, True)
        vbox.pack_start(statsbox, False)
        
        self.window.add(vbox)
        self.window.show_all()

    def put(self, pkt):
        assert pkt != None
        assert pkt.dict['order']
        
        if self.timebase == None:
            self.timebase = pkt.timestamp
            
        if self.search_string and not search_in_pkt(self.search_string, pkt):
            return
        
        timestamp = pkt.timestamp - self.timebase
        timestamp = '%.6f' % timestamp
        self.pktlist.append(None, [False, pkt.id, timestamp, pkt.src, pkt.dst, pkt.dict['order'][-1], pkt])
    
    def show_stats(self, stats=None):
        if stats:
            buf = '%d packets received, %d packets dropped, %d packets dropped by interface' % stats
            self.statsbar.set_text(buf)
        else:
            self.statsbar.set_text('')
    
    def __quit(self, *w):
        if self.sniffThread and self.sniffThread.isAlive():
            self.sniffThread.running = False
            self.sniffThread.join()
        gtk.main_quit()
    
    def __select_dev(self, combobox):
        self.eth = combobox.get_active_text()
        self.startbtn.set_sensitive(True)
    
    def __start(self, widget):
        assert self.sniffThread == None or self.sniffThread.running == False
        
        widget.set_sensitive(False)
        self.combobox.set_sensitive(False)
        clearcount()
        self.pktlist.clear()
        self.timebase = None
        
        self.sniffThread = SniffThread(self.eth, self.put, self.show_stats)
        self.sniffThread.running = True
        self.sniffThread.start()
        if self.filter_string:
            self.__do_filter()
        self.stopbtn.set_sensitive(True)
    
    def __stop(self, widget):
        assert self.sniffThread.running == True

        widget.set_sensitive(False)
        self.sniffThread.running = False
        self.sniffThread.join()
        self.sniffThread = None
        self.startbtn.set_sensitive(True)
        self.combobox.set_sensitive(True)
    
    def __filter(self, widget):
        self.filter_string = widget.filterentry.get_text()
        if self.sniffThread and self.sniffThread.running:
            self.__do_filter()
        else:
            widget.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#B5FFF3"))
    
    def __do_filter(self):
        cmd = self.filter_string
        try:
            if cmd:
                filter(cmd)
                self.filterbtn.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#6CFF66"))
            else:
                self.filterbtn.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("White"))
        except:
            self.filterbtn.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#FF6C66"))
    
    def __search(self, widget):
        to_be_remove = []
        to_be_add = []
        
        def __search_in_tree(model, path, iter):
            pkt = model.get_value(iter, 6)
            if not search_in_pkt(self.search_string, pkt):
                to_be_remove.append(iter)
        
        self.search_string = widget.searchentry.get_text()
        if self.search_string:
            self.pktlist.foreach(__search_in_tree)
            for pkt in self.hided_pkts:
                if search_in_pkt(self.search_string, pkt):
                    to_be_add.append(pkt)
        else:
            to_be_add = self.hided_pkts[0:]
        
        for iter in to_be_remove:
            self.hided_pkts.append(self.pktlist.get_value(iter, 6))
            self.pktlist.remove(iter)
        
        for pkt in to_be_add:
            self.hided_pkts.remove(pkt)
            self.put(pkt)
        
    def __textbox_refresh(self, data):
        buffer = self.textview.get_buffer()
        buffer.set_text('')
        
        hexes = map(ord, data)
        addr = 0
        ascii = ''
        
        def __try_ascii(hex):
            if 32 <= hex < 127:
                return chr(hex)
            else:
                return '.'
        
        for hex in hexes:
            if addr % 0x10 == 0:
                if ascii:
                    buffer.insert_at_cursor('  %s\n' % ascii)
                    ascii = ''
                buffer.insert_at_cursor('%04X  ' % addr)
            addr += 1
            ascii += __try_ascii(hex)
            buffer.insert_at_cursor('%02X ' % hex)
        if ascii:
            left = 0x10 - addr % 0x10
            if left == 0x10: left = 0
            buffer.insert_at_cursor('   ' * left)
            buffer.insert_at_cursor('  %s\n' % ascii)
    
    def __treebox_refresh(self, pkt):
        self.treestore.clear()
        if pkt:
            print pkt.dict
            def build_subtree(parent, d):
                for typ in d['order']:
                    if type(d[typ]) == dict:
                        t = self.treestore.append(parent, [typ, ''])
                        build_subtree(t, d[typ])
                    else:
                        value = str(d[typ])
                        self.treestore.append(parent, [typ, value])
            build_subtree(None, pkt.dict)
    
    def __select_row(self, selection):
        (store, pathlist) = selection.get_selected_rows()
        if pathlist == None or len(pathlist) != 1:
            data = ''
            pkt = None
        else:
            iter = store.get_iter(pathlist[0])
            pkt = store.get_value(iter, 6)
            data = pkt.data
        self.__textbox_refresh(data)
        self.__treebox_refresh(pkt)

if __name__ == '__main__':
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    libc.prctl(15, 'wiredog', 0, 0, 0)
    
    m = MainView()
    gtk.gdk.threads_init()
    gtk.gdk.threads_enter()
    gtk.main()
    gtk.gdk.threads_leave()
    
