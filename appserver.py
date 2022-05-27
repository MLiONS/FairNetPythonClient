# -*- coding: utf-8 -*-
"""
Created on Tue Oct 31 02:54:48 2019

@author: khandkar
Version:
    0.1 : 31-10-2019 : Basic adaptive streaming server
"""
__spec__ = None

from collections import namedtuple
import math

DEBUG = "ON"
ERROR = "ERROR"
SUCCESS = "SUCCESS"
IGNORE = "IGNORE"

MAX_DATA = 20000000*8
SEG_SIZE = (2500000*8/4)
# SEG_SIZE = 1000*8
BUFF_SIZE = 8192 * 4


MAX_TH = 7000000 #bps Convert it to bits?????
TX_WINDOW = (0.005*1)#s
# TX_WINDOW = 0.002 #s
# TX_WINDOW = 0 # Try
BSIZE = int(MAX_TH*TX_WINDOW)
DELTA_TH = math.ceil(BSIZE*0.01)
MIN_TH = 2000000
BSIZE_MIN = int(MIN_TH*TX_WINDOW)

# BSIZE_NORM = 40000
BSIZE_NORM = 50000 # Try
# BSIZE_NORM = 1250*8 

NUM_DIS_SEG = 1
DIS_SEG = []
NUM_DIS_PER_SEG = 1
DIS_PER_SEG = {}
KEEP_MIN_TH = []

server_socket = None
fdatap = None
ESNI = False

namestring_to_app_map = {"wynk.in":'https://wynk.in/music',
        "gaana.com":'https://gaana.com/',
        "jiosaavn.com": "https://www.jiosaavn.com/",
        "spotify.com": "https://www.spotify.com/",
        "music.amazon.in": "https://music.amazon.in/",
        "play.google.com/music": "https://play.google.com/music",
        "hotstar.com":"https://www.hotstar.com/",
        "primevideo.com":"https://www.primevideo.com/",
        "netflix.com":'https://www.netflix.com/',
        "youtube.com":'https://www.youtube.com/',
        "mxplayer.in":'https://www.mxplayer.in/',
        "hungama.com":'https://www.hungama.com',
        "zee5.com":'https://www.zee5.com/',
        "voot.com":'https://www.voot.com/',
        "erosnow.com":'https://erosnow.com/',
        "sonyliv.com":'https://www.sonyliv.com/',
        "STFD":"STFD"}

app_to_name_map = {'https://wynk.in/music': "WYNK",
                   'https://gaana.com/': "GAANA.COM",
                   "https://www.jiosaavn.com/":"SAAVN",
                   "https://www.spotify.com/":"SPOTIFY",
                   "https://music.amazon.in/" : "PRIMEMUSIC",
                   "https://play.google.com/music" : "GOOGLEPLAYMUSIC",
                   "https://www.hotstar.com/":"HOTSTAR",
                   "https://www.primevideo.com/":"PRIMEVIDEO",
                   'https://www.netflix.com/': "NETFLIX",
                   'https://www.youtube.com/': "YOUTUBE",
                   'https://www.mxplayer.in/': "MXPLAYER",
                   'https://www.hungama.com': "HUNGAMA",
                   'https://www.zee5.com/': "ZEE5",
                   'https://www.voot.com/': "VOOT",
                   'https://erosnow.com/': "EROSNOW",
                   'https://www.sonyliv.com/': "SONYLIV",
                   'STFD':"SPEEDTEST"}


app_to_file_map = {'https://wynk.in/music': "Media/WYNK",
                   'https://gaana.com/': "Media/GAANA.COM",
                   "https://www.jiosaavn.com/":"Media/SAAVN",
                   "https://www.spotify.com/":"Media/SPOTIFY",
                   "https://music.amazon.in/":"Media/PRIMEMUSIC",
                   "https://play.google.com/music":"Media/GPMUSIC",
                   "https://www.hotstar.com/":"Media/HOTSTAR",
                   "https://www.primevideo.com/":"Media/PRIMEVIDEO",
                   'https://www.netflix.com/': "Media/NETFLIX",
                   'https://www.youtube.com/': "Media/YOUTUBE",
                   'https://www.mxplayer.in/': "Media/MXPLAYER",
                   'https://www.hungama.com': "Media/HUNGAMA",
                   'https://www.zee5.com/': "Media/ZEE5",
                   'https://www.voot.com/': "Media/VOOT",
                   'https://erosnow.com/': "Media/EROSNOW",
                   'https://www.sonyliv.com/': "Media/SONYLIV",
                   'STFD': "Media/STFD"}

app_glitch_list = []
app_trdata_list = []
app_to_data = {}
client_to_tx_info = {}
app_to_hcode = {}
client_to_th_info = {}
cid_to_app_map = {}
cid_info = [] 
app_to_mth = {}

tx_info_struct = namedtuple("tx_info", ['ptime', 'ctime', 'pth', 'th', 'start_adpt'])


def sserver_calc_bth(cid, ptime, ctime, pth):
    th = 0
    if 0 == ptime :
        return th
    ct = ctime
    pt = ptime
    # tdiff = (int(ct) - int(pt))/1000
    tdiff = ct - pt
    tdiff = tdiff.total_seconds()
    # print("TDIFF = "+str(tdiff)+"s")
    th = SEG_SIZE / tdiff
    print("ID: "+str(cid) + "  Elapsed Time ="+str(tdiff)+"s  Throughput = " + str(th))
    return th


def sserver_get_bw_correction(app, ptime, ctime, pth, th):
    # print("Correction params: "+str(ptime)+" "+str(ctime)+" "+str(ipth)+" "+str(th))
    corr = 0
    d = 0
    if str(app) in KEEP_MIN_TH:
        mth = MIN_TH
    else:
        mth = MAX_TH
    # pth = tx_info['pth']
    # pth = ipth
    if pth == 0:
        pth = th
        corr = 0
        d = 0
    else:
        if th > mth:
            d = 0
            d = -(th - mth)*TX_WINDOW
            corr = 0
        elif th < MIN_TH:
            d = (MIN_TH-th)*TX_WINDOW
        else:
            if th < pth:
                if pth - th >= 750000:
                    diff = 0
                else:
                    diff = (pth - th)
                if pth > mth:
                    corr = DELTA_TH
                    d = diff*TX_WINDOW
                else:
                    corr = -DELTA_TH
                    d = -(diff)*TX_WINDOW
            else:
                corr = DELTA_TH
                if th - pth >= 750000:
                    diff = 0
                else:
                    diff = (th - pth)
                d = ((diff)*TX_WINDOW)
    corr = d
    # print("Correction = "+str(corr))
    return corr


def sserver_perform_adapt(capp, ptime, ctime, pth, th):
    import time
    corr = -1
    if ptime == 0:
        return corr
    corr = sserver_get_bw_correction(capp, ptime, ctime, pth, th)
    # print("Correction = " + str(corr))
    return corr

etdata = "SEG-END#"
letdata = len(etdata)
# print("ledata = "+str(letdata))


def sserver_get_oth(cid):
    mth = 0
    # print("CID = "+str(cid_info))
    # print("CTOTH = "+str(client_to_th_info))
    # print("Current cid "+str(cid))
    for ccid in cid_info:
        if ccid == cid:
            continue
        th = client_to_th_info[ccid]
        if mth < th:
            mth = th
    return mth


def stream_stored_app_data(c, cid, app, tx_window, is_dis_seg, blist, bsize):
    import sys
    import time
    import socket
    from datetime import datetime
    from io import StringIO
    # print(app)
    adata = app_to_data[app]
    data = adata[0]
    #fp = open("data","w")
    #fp.write(data)
    #fp.close()
    # ldata = len(data)
    # print("Data Len = "+str(len(data)))
    d_size = 0
    bcount = 0
    # bsize = int(client_to_tx_info[cid]/8) - passed as argument
    ssize = math.ceil(SEG_SIZE/8)
    #ssize_org = ssize
    #if app in app_trdata_list:
    #    ssize_mod = True
    #    ssize = ssize - (ssize*0.5)
    #    print("New seg size = "+str(ssize))
    # print("SSsiz = "+str(ssize))
    #print("bsize = "+str(bsize))
    #print("MAX_TH = "+str(MAX_TH))
    seg_data = ""
    seg_size = 0
    tdata1 = "BURST-END:"
    tdata2 = str(bsize)
    tdata3 = '#'
    htdata = tdata1 + tdata2 + tdata3
    lhtdata = len(htdata)
    # print("lhtdata = " + str(lhtdata))
    lrdata = bsize - lhtdata
    # print("lrdata = " + str(lrdata))
    
    #etdata = 'SEG-END'
    #letdata = len(etdata)
    # print("letdata = " + str(letdata))

    finalb = False
    slen = 0
    is_dis_applied = False

    while seg_size != ssize:
        try:
            if is_dis_seg :
                nbcount = bcount - 1
                # print("is_dis_applied = "+str(is_dis_applied))
                # print("NBCOUNT = "+str(nbcount))
                if nbcount in blist and str(app) in app_glitch_list and is_dis_applied is True:
                    oth = sserver_get_oth(cid)
                    # print("Other max th = "+str(oth))
                    bsize = int((oth*TX_WINDOW)/8)
                    # print("Restored bsize = "+str(bsize))
                    is_dis_applied = False 
                elif bcount in blist and str(app) in app_glitch_list:
                    # print("BCOUNT = "+str(bcount))
                    # print("BLIST = "+str(blist))
                    # print("CID = "+str(cid))
                    # print("Original bsize = "+str(bsize))
                    bsize = int(BSIZE_MIN/8)
                    # print("New bsize = "+str(bsize))
                    # print(cid_to_app_map[cid])
                    # print(app_glitch_list)
                    print("Glitch inserted for "+str(app) + " : " + str(cid))
                    is_dis_applied = True 
            if str(app) in KEEP_MIN_TH:
                bsize = int(BSIZE_MIN/8)
            lrdata = bsize - lhtdata
            if seg_size + bsize >= ssize:
                # print("End of segment " + str(lrdata))
                lrdata = lrdata - letdata
                # print("Last lrdata ="+str(lrdata))
                # print("Last bsize = "+str(lhtdata+lrdata+letdata))
                # print("Last SEG-SIZE = "+str(seg_size+bsize))
                lrdata = lrdata - (seg_size + bsize - ssize) 
                # print("Last lrdata = "+str(lrdata))
                # print("Last Updated bsize = "+str(lhtdata+lrdata+letdata))
                bsize = lhtdata+lrdata+letdata
                # x = input()
                finalb = True
            # print("d_size = " + str(d_size) + " : lrdata = " + str(lrdata))
            tdata = data[d_size:d_size + lrdata]
            # print(tdata)
            tdata = tdata + htdata
            if finalb:
                tdata = tdata + etdata
                seg_data += tdata #.strip().replace("\n","")
                hcode = java_string_hashcode(seg_data) # Try
                tdata = tdata + str(hcode)
            else:
                seg_data += tdata
            # slen = len(tdata)
            # print("Burst Length = "+str(slen))
            # tdata = "Content-Length: 625000VinodSKhandkar" #Try
            d_size += lrdata
            seg_size += bsize
            # seg_data += tdata
            # print("SEG_SIZE = "+str(seg_size))
            # print("SEG_DATA_LEN = "+str(len(seg_data)))
            tdataf = tdata.encode('utf-8')
            c.sendall(tdataf)
            bcount += 1
            if tx_window != 0:
                time.sleep(tx_window)
            # seg_size = ssize # Try
            # ssize = seg_size # Try 
            # x = input()
        except KeyboardInterrupt:
            break
        except c.error:
            print ("Socket error")
            break
    #print("Tdata = "+str(tdata))
    # print("SEG-DATA = "+str(seg_data))
    # hcode = java_string_hashcode(seg_data) # Try
    slen = len(seg_data)
    # print("SEG-LEN = "+str(slen))
    #fname = "seg_data.txt" 
    #fp = open(fname,"a")
    #fp.write(str(slen)+"\n")
    #fp.write(str(seg_data)+"\n")
    #fp.write(str(hcode)+"\n")
    #fp.close()
    # print("HASH Code = "+str(hcode))
    # print("Transmitted = "+str(seg_size) + " " + str(bsize) + " " + str(bcount))
    # x = input()
    # print("Sent: "+str(cid))
    # print("BCOUNT = "+str(bcount))
    return seg_size



def sserver_check_finish(cid, data):
    res = False
    data = data.decode("utf-8")
    data = data.split(" ")
    #print(data)
    if len(data) > 1:
        if "END" in data[1]:
            del cid_to_app_map[cid]
            print(str(cid) + "Download finished")
            res = True
    return res


def sserver_set_start_adpt(ctime, ptime, pth, th, c):
    apply = False
    # If rate of change of throughput in negative direction is greater than threshold , start adapt - TBD
    th_diff = pth - th
    if th_diff > 3000000:
        apply = True
    if c > 0:
        apply = True
    #apply = True
    return apply


def update_global_tx_params(max_th_mbps):
    global MAX_TH
    global BSIZE
    max_th_mbps = float(max_th_mbps)
    # print("MAX_TH = "+str(max_th_mbps))
    x = max_th_mbps
    # MAX_TH = float(max_th_mbps)*1000000
    # BSIZE = int(MAX_TH*TX_WINDOW)
    # print("Updated MAX_TH = "+str(MAX_TH))


def stream_stored(app, addr, ss):
    from datetime import datetime
    import socket
    import select
    import time
    rstatus = ERROR
    output_data = "Streaming Stored data \n"
    # print(output_data)
    print(app)
    c = 0
    ctime = 0
    ptime = 0
    th = 0
    pth = 0
    apply_adpt = False
    finish = False
    scount = 0
    # tx_info = tx_info_struct(0, 0, 0, True)
    client_addr = addr[0]
    client_port = addr[1]
    cid = sserver_get_client_id(client_port, client_addr)
    cid_info.append(cid)
    cid_to_app_map[cid] = app
    print("CID to APP Map : " + str(cid_to_app_map))
    dsize = 0
    rcount = 0
    seg_count = 0
    SND_BUF_SIZE = 0
    bsize = BSIZE_NORM
    while True:
        try:
            while True:
                try:
                    # print("Selecting ....")
                    rs, ws, es = select.select([ss], [], [])
                    if ss in rs:
                        rstatus = SUCCESS
                        break
                    if ss in es:
                        rstatus = ERROR
                        break
                except KeyboardInterrupt:
                    rstatus = ERROR
                    break
            # print(rstatus)
            if rstatus == SUCCESS:
                data = ss.recv(BUFF_SIZE)
                if data is None or data == b'':
                    continue
                rcount += 1
                #print(str(cid)+" : "+str(rcount))
                #print(data)
                # print("Recv : "+str(cid))
                finish = sserver_check_finish(cid, data)
                if finish is True:
                    rstatus = ERROR
                    break
                if "SPEED:" in str(data):
                    data1 = str(data,"utf-8").split("SPEED:")
                    data1 = data1[1].split(" ")[0]
                    if len(data1) > 1:
                        update_global_tx_params(data1)
                ctime = datetime.now()
                th = sserver_calc_bth(cid, ptime, ctime, pth)
                client_to_th_info[cid] = th 
                # apply_adpt = tx_info.start_adpt
                if not apply_adpt:
                    apply_adpt = sserver_set_start_adpt(ptime, ctime, pth, th, c)
                    print("Apply adpt = "+str(apply_adpt))
                    if apply_adpt:
                        # client_to_tx_info[cid] = int(MAX_TH*TX_WINDOW)
                        bsize = BSIZE
                        # print("bsize_min = " + str(client_to_tx_info[cid]) + "\n")
                        print("bsize_min = " + str(bsize) + "\n")
                if apply_adpt:
                    if SND_BUF_SIZE == 0:
                        SND_BUF_SIZE = 100000 #math.floor(BSIZE)
                        print("[+] "+str(addr)+" "+ str(ss)+" client accepted..")
                        bufsize = ss.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                        print ("Buffer size [Before]: " +str(bufsize))
                        ss.setsockopt( socket.SOL_SOCKET, socket.SO_SNDBUF, SND_BUF_SIZE)
                        bufsize = ss.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                        print ("Buffer size [After]: " +str(bufsize))
                    # tx_info = tx_info_struct(ptime, ctime, tx_info.pth, th, apply_adpt)
                    corr = sserver_perform_adapt(app, ctime, ptime, pth, th)
                    rstatus, bsize = sserver_update_client_data_tx(app, addr, int(corr), bsize)
                    # tx_info = tx_info_struct(tx_info.ptime, tx_info.ctime, th, 0, tx_info.start_adpt)
                    ptime = datetime.now()
                    # print("Previous Time:", time.asctime(time.localtime(time.time())))
                    if seg_count in DIS_SEG:
                        is_dis_seg = True
                        blist = DIS_PER_SEG[seg_count]
                        print("Segment detected ")
                    else:
                        is_dis_seg = False
                        blist = None
                    dsize += stream_stored_app_data(ss, cid, app, TX_WINDOW, is_dis_seg, blist, bsize)
                    pth = th
                    th = 0
                    seg_count += 1
                else:
                    SND_BUF_SIZE = 0
                    #client_to_tx_info[cid] = int(BSIZE_NORM)
                    c += 1
                    # print("Previous Time:", time.asctime(time.localtime(time.time())))
                    dsize += stream_stored_app_data(ss, cid, app, TX_WINDOW, False, None, BSIZE_NORM)
                    print("Burst sent without dynamic adaptation")
            else:
                rstatus = ERROR
                break
            #scount += 1
            if app in app_trdata_list:
                print("App detected " + str(cid) + ": " + str(dsize*8) + " : " + str(0.5*MAX_DATA))
                if dsize*8 >= 0.2*MAX_DATA:
                    break
            if MAX_DATA*6 < dsize*8:
                print(dsize)
                rstatus = SUCCESS
                break;
            # print("SEG Count = "+str(seg_count))
        except KeyboardInterrupt:
            break
    return rstatus


def sserver_start_stored_streaming(app, addr, c):
    rstatus = stream_stored(app, addr, c)
    #try:
    #    if c:
    #        c.close()
    #except KeyboardInterrupt:
    #   rstatus = ERROR 
    return rstatus


'''
def sserver_get_app_tx_info(addr):
    client_port = addr[1]
    client_addr = addr[0]
    client_id = sserver_get_client_id(client_port, client_addr)
    client_tx_info = client_to_tx_info[client_id]
    app_tx_info = client_tx_info[client_port]
    return app_tx_info

def sserver_set_app_tx_info(addr, app_tx_info):
    client_port = addr[1]
    client_addr = addr[0]
    client_id = sserver_get_client_id(client_port, client_addr)
    client_tx_info = client_to_tx_info[client_id]
    client_tx_info[client_port] = app_tx_info
'''

def mcl_store_report(report):
    import re
    import os
    m = re.search("ClientId:((\w+-)+\w+)", str(report), re.IGNORECASE)
    fname = m.group(1) + "-"
    m = re.search("Instance:(\d+[+]\d+)", str(report), re.IGNORECASE)
    pat = m.group(1)
    fname += pat
    fname = "Report/"+fname
    print(fname)
    if os.path.exists(fname):
        os.remove(fname)
    fp = open(fname,"a")
    fp.write(report)
    fp.close()


def mcl_receive_report(data, c):
    import os
    report = data
    if "Instance" not in report:
        while True:
            data = c.recv(BUFF_SIZE)
            data = data.decode('utf-8')
            #data = str(data)
            report += data
            if "Instance" in data:
                break;
    # print(report)
    mcl_store_report(report)
    print("Complete Report received ")

data_to_hashcode_map = {"GET https://www.hotstar.com/ HTTP/1.1\r\n":-2006517923}

def java_string_hashcode(s):
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000

def sserver_check_hashcode(data1):
    data = data1.decode("utf-8")
    data = str(data)
    #data = data.replace("\'","")
    data = data.replace("00","")
    #data = data.rstrip("\n")
    #data = data.rstrip("\r")
    #data = str(data1)
    # print(data)
    rhcode = java_string_hashcode(data)
    if (data in data_to_hashcode_map):
        shcode = data_to_hashcode_map[data]
    else:
        shcode = 0
    # print(str(shcode)+":"+str(rhcode))

def sserver_start_client_data_tx(c, addr):
    import gzip
    fname = None
    rstatus = ERROR
    ws = None
    data1 = c.recv(BUFF_SIZE)

    # sserver_check_hashcode(data1)
    # data = data.decode("utf-8")
    # print(data)

    # data = data.split(" ")
    #print(data1)
    data = str(data1)
    if "REPORT" in data:
        print("Report found")
        # data = data1.decode('utf-8')
        mcl_receive_report(data, c);
        rstatus = SUCCESS;
        return rstatus
        # sserver_process_report(data)

    data = data1.decode("utf-8")
    print("Received data = "+str(data.rstrip("\n")))
    app = "INVALID"
    if len(data) > 1:
        #if "https" in data[1]:
        # app = data[1]
        for sapp in namestring_to_app_map:
            # print(sapp)
            if sapp in data:
                print("App found")
                app = namestring_to_app_map[sapp]
                # print(app)
        print("Received App id : " + str(app))
        if app in app_to_file_map: 
            print("Handling stored data streaming")
            tdata = "OK"
            c.send(tdata.encode('UTF-8'))
            print("OK Sent ...")
            # tx_info = sserver_get_app_tx_info(addr)
            rstatus = sserver_start_stored_streaming(app, addr, c)
        else:
            d = str(addr) + " : Permission denied"
            c.sendall(d.encode('UTF-8'))
            c.close()
            print(d)
    else:
        d = str(addr) + " : Permission denied"
        c.sendall(d.encode('UTF-8'))
        c.close()
        print(d)

    return rstatus


def sserver_get_client_id(port, addr):
    client_id = str(addr)  + ":" + str(port)
    return client_id


def sserver_update_client_data_tx(app, addr, corr, bsize):
    rstatus = ERROR
    client_port = addr[1]
    client_addr = addr[0]
    client_id = sserver_get_client_id(client_port, client_addr)
    if corr == -1:
        if str(app) in KEEP_MIN_TH:
            bsize = BSIZE_MIN
        else:
            bsize = BSIZE
        print("bsize_min = " + str(bsize) + "\n")
    else:
        # bsize = client_to_tx_info[client_id] + corr
        bsize = bsize + corr
        if bsize <= 0:
            bsize = BSIZE
    # print("bsize = "+str(bsize) + "corr = " + str(corr) + "\n")
    tx_info = {client_id: bsize}
    # client_to_tx_info.update(tx_info)
    # print("sserver_update_client_data_tx : client_to_info : "+str(client_to_tx_info))
    return rstatus, bsize


def sserver_set_client_data_tx(addr, bsize):
    rstatus = ERROR
    client_port = addr[1]
    client_addr = addr[0]
    client_id = sserver_get_client_id(client_port, client_addr)
    tx_info = {client_id: bsize}
    # client_to_tx_info.update(tx_info)
    # print("sserver_set_client_data_tx : client_to_info : "+str(client_to_tx_info))
    return rstatus


def sserver_get_ssl_socket(c):
    import ssl
    ss = c
    context = ssl.SSLContext(ssl.PROTOCOL_TLS) #Original TLSv1
    # context.load_cert_chain('../SSL_cert/server.cert', '../SSL_cert/server.key')
    context.load_cert_chain('../SSL_cert/1/server.cert', '../SSL_cert/1/server.key')
    ss = context.wrap_socket(c,server_side=True)
    return ss 

def start_client_thread(c, addr):
    rstatus = sserver_set_client_data_tx(addr, BSIZE)
    if ESNI:
        c = sserver_get_ssl_socket(c)
    c = sserver_get_ssl_socket(c)
    # print("Client Thread : " + str(c))
    # print("Client Thread : " + str(addr) + " : " + str(client_to_tx_info))
    rstatus = sserver_start_client_data_tx(c, addr)
    # c.close()


def accept_client(s):
    import threading
    import select
    import socket
    import math
    rstatus = ERROR
    timeout = 1
    # a forever loop until we interrupt it or  
    # an error occurs 
    output_data = "[+]Waiting for client to connect \n"
    print(output_data)
    while True:
        # Establish connection with client. 
        try:
            while True:
                try:
                    rs, ws, es = select.select([s], [], [], timeout)
                    if s in rs:
                        rstatus = SUCCESS
                        break
                except KeyboardInterrupt:
                    rstatus = ERROR
                    break
            print("r: "+str(rs))
            print("w: "+str(ws))
            print("e: "+str(es))
            if rstatus == SUCCESS:
                SND_BUF_SIZE = math.floor(BSIZE/2)
                c, addr = s.accept()
                print("[+] "+str(addr)+" "+ str(c)+" client accepted..")
                # bufsize = c.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                # print ("Buffer size [Before]: " +str(bufsize))
                # c.close()
                # c.setsockopt( socket.SOL_SOCKET, socket.SO_SNDBUF, SND_BUF_SIZE)
                # bufsize = c.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                # print ("Buffer size [After]: " +str(bufsize))
                c2s = threading.Thread(target=start_client_thread, args=(c, addr))
                c2s.start()
            else:
                break
        except KeyboardInterrupt:
            if server_socket != None:
                server_socket.close()
            rstatus = ERROR
            break
    return rstatus


def setup_sserver(port, addr):
    import socket
    MAX_CONN = 0
    rstatus = ERROR
    s = None
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        server_socket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        output_data = "Client Side Socket creation successful \n"
        print(output_data)
        # Bind socket
        s.bind((addr, port))
        output_data = "Client Side Socket binding successful on" + ' ' + str(addr) + ':' + str(port) + '\n'
        print(output_data)
        # Bind socket
        # Configure socket to listen
        s.listen(MAX_CONN)
        output_data = "Client Side Socket listening \n"
        print(output_data)
        rstatus = SUCCESS
        output_data = "[+] Successfully setup streaming server [" + str(port) + "]" + '\n'
        print(output_data)
    except Exception as e:
        output_data = "Unable to setup socket\n" + str(e)
        print(output_data)
        rstatus = ERROR
    return rstatus, s


def sserver_fill_app_data(app, datafile):
    import time
    import binascii
    import math
    adata = []
    count = 0
    lline = int(SEG_SIZE/8)
    # print("P Lline = "+str(lline))
    # print("Datafile = "+str(datafile))
    filedesc = open(datafile, 'rb')
    # app = app.split("//")[1]
    # app = app.split(".")[0]
    # fdata = b'Content-Length: 625000\n'
    fdata1 = b'Content-Length: '
    fdata2 = str(lline).encode('utf-8')
    fdata = b''.join((fdata1,fdata2))
    fdata = "Content-Length: "+str(lline)
    # data = fdata.decode('utf-8')
    # fdata = binascii.b2a_hex(fdata).decode('utf-8')
    # print(fdata)
    fdlen = len(fdata)
    # print("fdlen = "+str(fdlen))
    ldata = len(fdata)
    lline = math.floor((lline - fdlen)*(2.9510/4)+(0.03*lline))
    # print("LLline = "+str(lline))
    # Fill exact length - TBD
    #print("Setting app data for " + str(app) + " : " + str(count * SEG_SIZE * 100 / MAX_DATA) + "% done", end='\r')
    # for line in filedesc:
    # print("lline size = "+str(lline) + '  \n')
    while True:
        data = fdata
        linel = lline 
        line = ""
        rlen = 45
        while linel != 0:
            rline = filedesc.read(rlen)
            rline = binascii.b2a_uu(rline)
            line += rline.decode('utf-8').rstrip("\n")
            linel = (linel - rlen ) % lline
            if linel < rlen:
                rlen = linel
        # print(line)
        # print(line)
        if count * SEG_SIZE  >= MAX_DATA:
            break
        # data = binascii.b2a_hex(data)
        # print(data)
        # data = data.decode("utf-8")
        # print(data)
        line = line.rstrip("\n").replace("\"","").replace("\'","")
        data = data + line
        # print("Head + Data len = "+str(len(data)))
        # data = b''.join((data, line))
        ldata = ldata + lline*(4/3)
        # print("Ldata = "+str(ldata))
        # print("Data Len = "+str(len(data)))
        # x = input()
        adata.append(data)
        #fp = open("data.txt","w")
        #fp.write(str(data))
        #fp.close()
        # hcode = java_string_hashcode(str(data))
        # app_to_hcode[app] = hcode
        # print("Data size = "+str(len(data)) + '  \n')
        data = fdata #b'Content-Length: 6250000\r\n'
        count += 1
        # print("Count = "+str(count))
        #print("Setting app data for " + str(app) + " : " + str(count * SEG_SIZE * 100 / MAX_DATA) + "% done",
        #      end='\r')
        ldata = len(data)
        #time.sleep(0.001)
    # print("Segement size = "+str(len(adata[0])))
    return adata


def sserver_setup_app_data(app):
    datafile = app_to_file_map[app]
    app_data = sserver_fill_app_data(app, datafile)
    app_to_data[app] = app_data

def setup_test_param_00():
    # Multiple service discriminated
    global KEEP_MIN_TH 
    KEEP_MIN_TH = ['https://www.youtube.com/', 'https://www.primevideo.com/', 'https://www.hotstar.com/', 'https://www.netflix.com/', 'https://gaana.com', 'https://www.spotify.com']


def setup_test_param_01():
    # Single service discriminated
    global KEEP_MIN_TH 
    # KEEP_MIN_TH = ['https://www.youtube.com/']
    KEEP_MIN_TH = ['https://wynk.in/music']
    

def setup_test_param_02():
    # Low throughput for multiple service including service under test, but one service with higher throughput
    # Expected : Threshold algo detects differentiation 
    global KEEP_MIN_TH
    KEEP_MIN_TH = ['https://www.youtube.com/', 'https://www.primevideo.com/', 'https://www.hotstar.com/']


def setup_test_param_03():
    # Low throughput for all service including service under test
    # Expected : Threshold algo detects differentiation 
    global KEEP_MIN_TH
    KEEP_MIN_TH = ['https://www.youtube.com/', 'https://www.primevideo.com/', 'https://www.hotstar.com/', 'https://www.netflix.com/']


def setup_test_param_04():
    # TS : Single glitche in single segment - Working 
    i = 0
    j = 7
    l = 0
    dps = []
    NUM_DIS_SEG = 1
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 8
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_param_05():
    # TS :Multiple glitched in service under test
    # Result : No differentiation
    app_glitch_list = ['https://www.youtube.com/']
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 3
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 9
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))




def setup_test_param_06():
    # TS : Few glitched in srvices including service under test
    # Result : No differentiation
    global app_glitch_list
    app_glitch_list = ['https://www.primevideo.com/', 'https://www.youtube.com/']
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 3
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 5
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_param_07():
    # TS : Few glitched in srvices other than service under test
    # Result : No traffic differentiation
    global app_glitch_list
    app_glitch_list = ['https://www.primevideo.com/']
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 3
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 5
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))



def setup_test_param_08():
    # TS : Multiple systematic glitches per segment spread over multiple segments uniformly - Working 
    # Result : Traffic differentiation
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 12 #5
    NUM_DIS_PER_SEG =  100 #3
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 1
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 2
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_param_08_py():
    # TS : Multiple systematic glitches per segment spread over multiple segments uniformly - Working 
    # Result : Traffic differentiation
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 12 #5
    NUM_DIS_PER_SEG =  50 #3
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 1
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 2
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))



def setup_test_param_09():
    # TS : few systematic glitches per segment spread over multiple segments uniformly - Working 
    # Result : No differentiation
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 3 
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 8
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_param_10():
    global app_glitch_list
    app_glitch_list = ['https://www.primevideo.com/', 'https://www.youtube.com/']
    # TS : Multiple systematic glitches per segment spread over multiple segments uniformly - Working 
    # Result : Traffic differentiation
    setup_test_param_08_py()


def setup_test_param_11():
    global app_glitch_list
    app_glitch_list = ['https://www.primevideo.com/', 'https://www.netflix.com/']
    # TS : Multiples systematic glitches per segment spread over multiple segments uniformly - Working 
    # Result : No diffferentiation
    setup_test_param_08()



def setup_test_param_12():
    # Blocking test app
    # Result : blocking detected
    global app_trdata_list
    app_trdata_list = ['https://www.youtube.com/']

def setup_test_param_13():
    # TS : Few systematic glitched in srvices other than service under test
    # Result : NO differentiation
    setup_test_param_00()
    global app_glitch_list
    app_glitch_list = ['https://www.primevideo.com/']
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 3
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 5
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_param_14():
    # Many systemtic glitches in throughput for services other than service under test which is discriminated
    # Resut : Differentiation
    setup_test_param_01()
    global app_glitch_list
    app_glitch_list = ['https://www.primevideo.com/']
    i = 0
    j = 5
    l = 0
    dps = []
    NUM_DIS_SEG = 12 
    NUM_DIS_PER_SEG = 100
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 8
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_param_try():
    # TS : Multiple glitches per segment spread over multiple segments uniformly - Working 
    i = 0
    j = 4
    l = 0
    dps = []
    NUM_DIS_SEG = 10
    NUM_DIS_PER_SEG = 1
    while i < NUM_DIS_SEG:
        DIS_SEG.append(j)
        k = 10
        while l < NUM_DIS_PER_SEG:
            dps.append(k)
            k += 2
            l += 1
        DIS_PER_SEG[j] = dps 
        i += 1
        j += 4
    print("DIS_SEG = "+str(DIS_SEG))
    print("DIS_PER_SEG = "+str(DIS_PER_SEG))


def setup_test_params():
    #setup_test_param_00() # Multiple services differentiated 
    #setup_test_param_01() # Single service differentiated
    # setup_test_param_12() # Frequent Connection lost
    print("App glitch list "+str(app_glitch_list))


def sserver(port, addr):
    import os
    s = None
    try:
        print('Hashseed is', os.getenv('PYTHONHASHSEED'))
        output_data = "[+] Setting up streaming server [" + str(port) + "]" + '\n'
        print(output_data)
        print("TX_WINDOW = "+str(TX_WINDOW)+"ms")
        print("Initial burst size = "+str(BSIZE)+"b")
        print("Burst correction = "+str(DELTA_TH)+"b"+'\n')
        print("Supported Apps:")
        setup_test_params()
        for app in app_to_file_map:
            print(str(app_to_name_map[app]))
            sserver_setup_app_data(app)
            # print("Data hashcode = "+str(app_to_hcode[app]))
        rstatus, s = setup_sserver(port, addr)
        # output_data = "S= " + str(s) + "rstatus=" + str(rstatus) + '\n'
        if ERROR == rstatus:
            output_data = "Exiting due to server socket error 1\n"
            print(output_data)
            return rstatus
        # Accept client, receive data from client, connect to remote server,
        # and start data flow
        fname = "seg_data.txt" 
        if os.path.exists(fname):
            os.remove(fname)

        while 1:
            rstatus = accept_client(s)
            if ERROR == rstatus:
                output_data = "sserver:1:Exiting due to error\n"
                if s:
                    s.close()
                return rstatus
    except KeyboardInterrupt:
        if s:
            s.close()
        output_data = "\n Application exiting due to user interruption\n"
        rstatus = ERROR
    return rstatus


## Webserver If 

# wsif_addr = "10.119.21.43"
wsif_addr = ""
wsif_port = 8085

def inform_ws(status, addr, port, c):
    sdata = status + "\r\n" + addr + "\r\n" + str(port) 
    print("Informing ws" + sdata)
    c.sendall(sdata.encode('utf-8'))

def start_wsif_thread(c, as_port, as_addr):
    status = "RUNNING"
    # Upgrade connection to SSL-connection
    c = sserver_get_ssl_socket(c)
    # Get the clientId from client
    comm = c.recv()
    comm = comm.decode('utf-8')
    print("Command = " + str(comm))
    # Provide application server address to webserver
    if "REQUEST" == comm:
        inform_ws(status, as_addr, as_port, c)
    else:
        print("Invalid command from webserver")
        c.close()


def accept_ws(s, as_port, as_addr):
    import threading
    import select
    import socket
    import math
    rstatus = ERROR
    timeout = 1
    # a forever loop until we interrupt it or  
    # an error occurs 
    output_data = "[+]Waiting for webserver to connect \n"
    print(output_data)
    while True:
        # Establish connection with client. 
        try:
            while True:
                try:
                    rs, ws, es = select.select([s], [], [], timeout)
                    if s in rs:
                        rstatus = SUCCESS
                        break
                except KeyboardInterrupt:
                    rstatus = ERROR
                    break
            print("r: "+str(rs))
            print("w: "+str(ws))
            print("e: "+str(es))
            if rstatus == SUCCESS:
                c, addr = s.accept()
                c2s = threading.Thread(target=start_wsif_thread, args=(c, as_port, as_addr, ))
                c2s.start()
            else:
                break
        except KeyboardInterrupt:
            rstatus = ERROR
            break
    return rstatus


def ws_setup_wsif(port, addr):
    import socket
    MAX_CONN = 0
    rstatus = ERROR
    s = None
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        server_socket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        output_data = "Client Side Socket creation successful \n"
        print(output_data)
        # Bind socket
        s.bind((addr, port))
        output_data = "Webserver Side Socket binding successful on" + ' ' + str(addr) + ':' + str(port) + '\n'
        print(output_data)
        # Bind socket
        # Configure socket to listen
        s.listen(MAX_CONN)
        output_data = "Webserver Side Socket listening \n"
        print(output_data)
        rstatus = SUCCESS
        output_data = "[+] Successfully setup web server interface [" + str(port) + "]" + '\n'
        print(output_data)
    except Exception as e:
        output_data = "Unable to setup Webserver socket\n" + str(e)
        print(output_data)
        rstatus = ERROR
    return rstatus, s


def webserver_if(port, addr, as_port, as_addr):
    import os
    s = None
    try:
        rstatus, s = ws_setup_wsif(port, addr)
        if ERROR == rstatus:
            output_data = "Exiting due to server socket error 1\n"
            print(output_data)
            return rstatus
        while 1:
            rstatus = accept_ws(s, as_port, as_addr)
            if ERROR == rstatus:
                output_data = "sserver:1:Exiting due to error\n"
                if s:
                    s.close()
                return rstatus
    except KeyboardInterrupt:
        if s:
            s.close()
        output_data = "\n Application exiting due to user interruption\n"
        rstatus = ERROR
    return rstatus


def ws_get_hostname():
    import socket
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    return ip_addr


# ISP NAME
def start_inif_thread(c, addr):
    from isp import send_isp_name
    # Upgrade connection to SSL-connection
    # c = sserver_get_ssl_socket(c)
    # Get the command tag as IPADDR
    comm = c.recv(BUFF_SIZE)
    comm = comm.decode('utf-8')
    print("Command = " + str(comm))
    # Provide application server address to webserver
    if "IPADDR" in comm:
        send_isp_name(c, addr)
    else:
        print("Invalid command from user client")
        c.close()


def accept_inr(s):
    import threading
    import select
    import socket
    import math
    rstatus = ERROR
    timeout = 1
    # a forever loop until we interrupt it or  
    # an error occurs 
    output_data = "[+]Waiting for webserver to connect \n"
    print(output_data)
    while True:
        # Establish connection with client. 
        try:
            while True:
                try:
                    rs, ws, es = select.select([s], [], [], timeout)
                    if s in rs:
                        rstatus = SUCCESS
                        break
                except KeyboardInterrupt:
                    rstatus = ERROR
                    break
            print("r: "+str(rs))
            print("w: "+str(ws))
            print("e: "+str(es))
            if rstatus == SUCCESS:
                c, addr = s.accept()
                c2s = threading.Thread(target=start_inif_thread, args=(c, addr, ))
                c2s.start()
            else:
                break
        except KeyboardInterrupt:
            rstatus = ERROR
            break
    return rstatus


def setup_inif(port, addr):
    import socket
    MAX_CONN = 0
    rstatus = ERROR
    s = None
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        server_socket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        output_data = "Client Side Socket creation successful \n"
        print(output_data)
        # Bind socket
        s.bind((addr, port))
        output_data = "ISP name Socket binding successful on" + ' ' + str(addr) + ':' + str(port) + '\n'
        print(output_data)
        # Bind socket
        # Configure socket to listen
        s.listen(MAX_CONN)
        output_data = "ISP name Socket listening \n"
        print(output_data)
        rstatus = SUCCESS
        output_data = "[+] Successfully setup ISP name interface [" + str(port) + "]" + '\n'
        print(output_data)
    except Exception as e:
        output_data = "Unable to setup ISP name socket\n" + str(e)
        print(output_data)
        rstatus = ERROR
    return rstatus, s


def isp_name_if(port, addr):
    import os
    s = None
    try:
        rstatus, s = setup_inif(port, addr)
        if ERROR == rstatus:
            output_data = "Exiting due to server socket error 1\n"
            print(output_data)
            return rstatus
        while 1:
            rstatus = accept_inr(s)
            if ERROR == rstatus:
                output_data = "sserver:1:Exiting due to error\n"
                if s:
                    s.close()
                return rstatus
    except KeyboardInterrupt:
        if s:
            s.close()
        output_data = "\n Application exiting due to user interruption\n"
        rstatus = ERROR
    return rstatus


inif_addr = ""
inif_port = 8085
# ISP NAME


def sserver_main(port, addr):
    import threading
    rstatus = ERROR
    try:
        s = threading.Thread(target=isp_name_if, args=(inif_port, inif_addr))
        s.start()
        rstatus = sserver(port, addr)
    except KeyboardInterrupt:
        output_data = "\n Application exiting due to user interruption\n"
        rstatus = ERROR
        return rstatus


if __name__ == '__main__':
    lport = 443
    laddr = ''
    sserver_main(lport, laddr)
