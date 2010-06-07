#!/usr/bin/env python

import gobject
import gtk
import os
import sys
import pango
import threading
import time

from lib.parse import *
from lib.tool import *

class SniffThread(threading.Thread):
    def __init__(self, eth, mainview):
        threading.Thread.__init__(self, name='sniff')
        self.running = False
        self.mainview = mainview
        self.eth = eth
        self.need_filter = False
        
    def show_pkt(self, *n):
        if not n[1]:
            return
        pkt = parse(*n)
        self.mainview.put(pkt)
#        self.disp_s(stats())

    def request_filter(self):
        self.need_filter = True
    
    def do_filter(self):
        assert self.need_filter
        self.mainview.do_filter()
        self.need_filter = False

    def run(self):
        open_live(self.eth)
        self.mainview.show_stats()
        while self.running:
            if self.need_filter:
                self.do_filter()
            try:
                n = next()
                if n == None:
                    time.sleep(0.01)
                else:
                    self.show_pkt(*n)
            except:
                import traceback
                traceback.print_exc(file=sys.stderr)
        self.mainview.show_stats(stats())
        close_sniff()

def dump_data(data):
    buffer = ''
    
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
                buffer += '  %s\n' % ascii
                ascii = ''
            buffer += '%04X  ' % addr
        addr += 1
        ascii += __try_ascii(hex)
        buffer += '%02X ' % hex
    if ascii:
        left = 0x10 - addr % 0x10
        if left == 0x10: left = 0
        buffer += '   ' * left
        buffer += '  %s\n' % ascii
    return buffer

def print_pkt(pkt):
    buffer = ''
    if pkt:
        buffer += time.strftime('Time: %Y-%m-%d %H:%M:%S', 
                                time.localtime(pkt.timestamp))
        buffer += ('%.6f\n' % (pkt.timestamp - int(pkt.timestamp)))[1:]
        def print_indent(i):
            return '  ' * i
        def build_subtree(indent, d):
            buf = ''
            for typ in d['order']:
                buf += print_indent(indent)
                buf += typ
                if type(d[typ]) == dict:
                    buf += '\n'
                    buf += build_subtree(indent+1, d[typ])
                elif type(d[typ]) == tuple:
                    buf += ': %s\n' % d[typ][0]
                    buf += dump_data(d[typ][1])
                else:
                    buf += ': %s\n' % d[typ]
            return buf
        buffer += build_subtree(0, pkt.dict)
        buffer += 'data:\n'
        buffer += dump_data(pkt.data)
        buffer += '\n'
    return buffer

class MainView:
    def __init__(self, logname=''):
        self.sniffThread = None
        self.timebase = None
        self.eth = None
        self.search_string = ''
        self.filter_string = ''
        self.hided_pkts = []
        self.logfile = None
        
        if logname:
            try:
                self.logfile = open(logname, 'w')
                sys.stderr = self.logfile
            except IOError:
                try: self.logfile.close()
                except IOError: pass
                self.logfile = None
        
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
        savebtn.connect('clicked', self.__save)
        
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
        filterbtn.connect('clicked', self.__filter_clicked)
        filterentry.connect('activate', self.__filter)
        
        filterbar = gtk.HBox()
        filterbar.pack_start(filterentry, True)
        filterbar.pack_start(filterbtn, False)
        
        searchbtn = gtk.Button('search')
        searchbtn.searchentry = searchentry = gtk.Entry()
        searchbtn.connect('clicked', self.__search_clicked)
        searchentry.connect('activate', self.__search)
        
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
        pktlist.pkt = None
        pktlist.PKT_INDEX = 6
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
            
        for i in range(1, pktlist.PKT_INDEX):
            __render = gtk.CellRendererText()
            __column = gtk.TreeViewColumn(column_heads[i])
            __column.pack_start(__render, False)
            __column.set_resizable(True)
            __column.set_sort_column_id(i)
            __column.set_cell_data_func(__render, __text_cell_func, i)
            listview.append_column(__column)
        
        listscroll = gtk.ScrolledWindow()
        listscroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        listscroll.set_shadow_type(gtk.SHADOW_IN)
        listscroll.add(listview)
        
        listbox = gtk.HBox()
        listbox.pack_start(listscroll, True)
        
        self.treestore = treestore = gtk.TreeStore(
                                  gobject.TYPE_STRING, 
                                  gobject.TYPE_PYOBJECT,
                                  )
        
        def __do_expand(treeview, path, view_column):
            if treeview.row_expanded(path):
                treeview.collapse_row(path)
            else:
                treeview.expand_to_path(path)
        
        treeview = gtk.TreeView(treestore)
        treeview.set_headers_visible(False)
        treeview.get_selection().connect('changed', self.__show_detail)
        treeview.connect('row-activated', __do_expand)
        
        __render = gtk.CellRendererText()
        __column = gtk.TreeViewColumn()
        __column.pack_start(__render, False)
        __column.set_cell_data_func(__render, __text_cell_func, 0)
        treeview.append_column(__column)
        
        def __data_cell_func(column, cell, model, iter):
            data = model.get_value(iter, 1)
            if type(data) == tuple:
                assert len(data) == 2
                text = data[0]
            else:
                text = str(data)
            cell.set_property('font-desc', pango.FontDescription('Monospace 10'))
            cell.set_property('text', text)
        
        __render = gtk.CellRendererText()
        __column = gtk.TreeViewColumn()
        __column.pack_start(__render, False)
        __column.set_cell_data_func(__render, __data_cell_func)
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
        textscroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
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

    def put(self, pkt, search_check=True):
        assert pkt != None
        assert pkt.dict['order']
        
        if self.timebase == None:
            self.timebase = pkt.timestamp
            
        if search_check and self.search_string and not is_match(self.search_string, pkt):
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
    
    def do_filter(self):
        cmd = self.filter_string
        try:
            if cmd:
                filter(cmd)
                self.filterbtn.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#6CFF66"))
            else:
                self.filterbtn.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("White"))
        except:
            self.filterbtn.filterentry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#FF6C66"))
    
    def __quit(self, *w):
        if self.sniffThread and self.sniffThread.isAlive():
            self.sniffThread.running = False
            self.sniffThread.join()
        self.logfile.close()
        gtk.main_quit()
    
    def __save(self, widget):
        fc = gtk.FileChooserDialog('Select a file to save', 
                                   self.window,
                                   gtk.FILE_CHOOSER_ACTION_SAVE,
                                   (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                    gtk.STOCK_SAVE, gtk.RESPONSE_OK),
                                   )
        fc.run()
        filename = fc.get_filename()
        fc.destroy()
        try:
            with open(filename, 'w') as f:
                for row in self.pktlist:
                    if row[0]:
                        f.write('#' * 20)
                        f.write('\n')
                        f.write(print_pkt(row[self.pktlist.PKT_INDEX]))
        except IOError:
            d = gtk.MessageDialog(self.window, 0,
                                  gtk.MESSAGE_ERROR,
                                  gtk.BUTTONS_CLOSE,
                                  'Error: Can not write to file "%s"' % filename,
                                  )
            d.run()
            d.destroy()
    
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
        
        self.sniffThread = SniffThread(self.eth, self)
        self.sniffThread.running = True
        self.sniffThread.start()
        if self.filter_string:
            self.__request_filter()
        self.stopbtn.set_sensitive(True)
    
    def __stop(self, widget):
        assert self.sniffThread.running == True

        widget.set_sensitive(False)
        self.sniffThread.running = False
        self.sniffThread.join()
        self.sniffThread = None
        self.startbtn.set_sensitive(True)
        self.combobox.set_sensitive(True)
    
    def __filter_clicked(self, widget):
        self.__filter(widget.filterentry)
    
    def __filter(self, entry):
        self.filter_string = entry.get_text()
        if self.sniffThread and self.sniffThread.running:
            self.__request_filter()
        else:
            entry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#B5FFF3"))
    
    def __request_filter(self):
        self.sniffThread.request_filter()
    
    def __search_clicked(self, widget):
        self.__search(widget.searchentry)
    
    def __do_search(self):
        to_be_remove = []
        to_be_add = []
        s = self.search_string
        
        def __search_in_tree(model, path, iter):
            pkt = model.get_value(iter, self.pktlist.PKT_INDEX)
            if not is_match(s, pkt):
                to_be_remove.append(iter)
        
        if s:
            self.pktlist.foreach(__search_in_tree)
            for pkt in self.hided_pkts:
                if is_match(s, pkt):
                    to_be_add.append(pkt)
        else:
            to_be_add = self.hided_pkts[0:]
        
        for iter in to_be_remove:
            self.hided_pkts.append(self.pktlist.get_value(iter, self.pktlist.PKT_INDEX))
            self.pktlist.remove(iter)
        
        for pkt in to_be_add:
            self.hided_pkts.remove(pkt)
            self.put(pkt, False)
        
    def __search(self, entry):
        s = entry.get_text()
        if s_check(s):
            self.search_string = s
            self.__do_search()
            if s:
                entry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#6CFF66"))
            else:
                entry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("White"))
        else:
            entry.modify_base(gtk.STATE_NORMAL, gtk.gdk.color_parse("#FF6C66"))
        
    def __textbox_refresh(self, data):
        buffer = self.textview.get_buffer()
        buffer.set_text('')
        buffer.insert_at_cursor(dump_data(data))
    
    def __treebox_refresh(self, pkt):
        self.treestore.clear()
        if pkt:
#            print pkt.dict
            def build_subtree(parent, d):
                for typ in d['order']:
                    if type(d[typ]) == dict:
                        t = self.treestore.append(parent, [typ, ''])
                        build_subtree(t, d[typ])
                    else:
                        self.treestore.append(parent, [typ, d[typ]])
            build_subtree(None, pkt.dict)
    
    def __select_row(self, selection):
        (store, pathlist) = selection.get_selected_rows()
        if pathlist == None or len(pathlist) != 1:
            data = ''
            pkt = None
        else:
            iter = store.get_iter(pathlist[0])
            pkt = store.get_value(iter, self.pktlist.PKT_INDEX)
            data = pkt.data
        store.pkt = pkt
        self.textview.is_detail = False
        self.__textbox_refresh(data)
        self.__treebox_refresh(pkt)
#        print print_pkt(pkt)

    def __show_detail(self, selection):
        (store, pathlist) = selection.get_selected_rows()
        if pathlist == None or len(pathlist) != 1:
            return
        else:
            iter = store.get_iter(pathlist[0])
            data = store.get_value(iter, 1)
            if type(data) == tuple:
                self.textview.is_detail = True
                self.__textbox_refresh(data[1])
            elif self.textview.is_detail:
                self.textview.is_detail = False
                self.__textbox_refresh(self.pktlist.pkt.data)

class Watcher:
    def __init__(self):
        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()
    
    def watch(self):
        try:  
            os.wait()  
        except KeyboardInterrupt:  
            self.kill()
        sys.exit()  
  
    def kill(self):  
        try:
            import signal
            os.kill(self.child, signal.SIGKILL)  
        except OSError: pass

class NullPrinter:
    def write(self, s):
        pass

if __name__ == '__main__':
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    libc.prctl(15, 'wiredog', 0, 0, 0)
    
    Watcher()
    storederr = sys.stderr
    sys.stdout = NullPrinter()
    m = MainView('err.log')
    gtk.gdk.threads_init()
    gtk.gdk.threads_enter()
    gtk.main()
    gtk.gdk.threads_leave()
    sys.stderr = storederr
