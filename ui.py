#!/usr/bin/env python

import gobject
import gtk
import threading

from lib.parse import *

class SniffThread(threading.Thread):
    def __init__(self, disp_f):
        threading.Thread.__init__(self, name='sniff')
        self.running = False
        self.disp_f = disp_f
    
    def run(self):
        open('wlan0')
        while self.running:
            n = next()
            if n:
                try:
                    pkt = parse(*n)
                    print pkt.dict
                    self.disp_f(pkt)
                except KeyboardInterrupt:
                    break
                except:
                    import traceback
                    import sys
                    traceback.print_exc(file=sys.stderr)
        print 'close'
        close()

class MainView:
    def __init__(self):
        self.sniffThread = SniffThread(self.put)
        
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_size_request(800, 500)
        self.window.connect('delete-event', self.__quit)
        
        self.startbtn = startbtn = gtk.Button('start')
        startbtn.set_sensitive(True)
        startbtn.connect('clicked', self.__start)
        
        self.stopbtn = stopbtn = gtk.Button('stop')
        stopbtn.set_sensitive(False)
        stopbtn.connect('clicked', self.__stop)
        
        savebtn = gtk.Button('save')
        
        toolbar = gtk.HBox(False, 10)
        toolbar.pack_start(startbtn, False)
        toolbar.pack_start(stopbtn, False)
        toolbar.pack_start(savebtn, False)
        
        filterbtn = gtk.Button('filter')
        filterbtn.filterentry = filterentry = gtk.Entry()
        
        filterbar = gtk.HBox()
        filterbar.pack_start(filterentry, True)
        filterbar.pack_start(filterbtn, False)
        
        searchbtn = gtk.Button('search')
        searchbtn.searchentry = searchentry = gtk.Entry()
        
        searchbar = gtk.HBox()
        searchbar.pack_start(searchentry, True)
        searchbar.pack_start(searchbtn, False)
        
        toolbar2 = gtk.HBox(False)
        toolbar2.pack_start(filterbar, True)
        toolbar2.pack_start(gtk.SeparatorToolItem(), False)
        toolbar2.pack_start(searchbar, True)
        
        self.pktlist = pktlist = gtk.TreeStore(gobject.TYPE_BOOLEAN, 
                                gobject.TYPE_INT,
                                gobject.TYPE_DOUBLE,
                                gobject.TYPE_STRING,
                                gobject.TYPE_STRING,
                                gobject.TYPE_STRING,
                                gobject.TYPE_OBJECT, 
                                )
        listview = gtk.TreeView(pktlist)
        listview.connect('select-cursor-row', self.__select_row)
        
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
            text = str(text)
            cell.set_property('text', text)
            
        for i in range(1, 6):
            __render = gtk.CellRendererText()
            __column = gtk.TreeViewColumn(column_heads[i])
            __column.pack_start(__render, False)
            __column.set_cell_data_func(__render, __text_cell_func, i)
            listview.append_column(__column)
        
        listscroll = gtk.ScrolledWindow()
        listscroll.set_policy(gtk.POLICY_NEVER, gtk.POLICY_ALWAYS)
        listscroll.set_shadow_type(gtk.SHADOW_IN)
        listscroll.add(listview)
        
        listbox = gtk.HBox()
        listbox.pack_start(listscroll, True)
        
        treebox = gtk.HBox()
        
        textview = gtk.TextView()
        textview.set_editable(False)
        textview.set_cursor_visible(False)
        
        textscroll = gtk.ScrolledWindow()
        textscroll.set_policy(gtk.POLICY_NEVER, gtk.POLICY_ALWAYS)
        textscroll.set_shadow_type(gtk.SHADOW_IN)
        textscroll.add(textview)
        
        textbox = gtk.HBox()
        textbox.pack_start(textscroll)
        
        infobox = gtk.VBox()
        
        infobox.pack_start(listbox, True)
        infobox.pack_start(treebox, True)
        infobox.pack_start(textbox, True)
        
        vbox = gtk.VBox()
        vbox.pack_start(toolbar, False)
        vbox.pack_start(toolbar2, False)
        vbox.pack_start(infobox, True)
        
        self.window.add(vbox)
        self.window.show_all()

    def put(self, pkt):
        assert pkt != None
        print pkt.dict
        self.pktlist.append(None, [False, 0, pkt.timestamp, pkt.src, pkt.dst, pkt.dict['order'][0], pkt])
    
    def __quit(self, *w):
        if self.sniffThread.running:
            self.sniffThread.running = False
            self.sniffThread.join()
        gtk.main_quit()
    
    def __start(self, widget):
        assert self.sniffThread.running == False
        
        widget.set_sensitive(False)
        self.sniffThread.running = True
        self.sniffThread.start()
        self.stopbtn.set_sensitive(True)
    
    def __stop(self, widget):
        assert self.sniffThread.running == True

        widget.set_sensitive(False)
        self.sniffThread.running = False
        self.sniffThread.join()
        self.startbtn.set_sensitive(True)
    
    def __select_row(self, *w):
        print w

if __name__ == '__main__':
    m = MainView()
    gtk.gdk.threads_init()
    gtk.gdk.threads_enter()
    gtk.main()
    gtk.gdk.threads_leave()
    
