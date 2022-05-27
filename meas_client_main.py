# -*- coding: utf-8 -*-

"""
Created on Tue May 14 02:29:48 2019

@author: khandkar
Version:
    0.1 : 14-05-2019 : Meas client python script dev started
    0.2 : 18-05.2019 : 10MB video downloaded successfully with sample HOTSTAR replay script
    0.3 : 20-05-2019 : Added support for per APP and consolidated performance measurements, throughput and Inter-arrival time
    0.4 : 23-05-2019 : Added support to handle multiple APPs 
"""

__spec__ = None

# Imports
from scapy.all import *
from meas_client_global_const import *
from meas_client_utils import mcl_fopen, mcl_fclose, mcl_fwrite, mcl_copy_file
from meas_client_downloader_main import mcl_start_download
from meas_client_packet_sniff import mcl_sniff_packets, mcl_get_pkts_from_sniffer, mcl_join_sniffer
from meas_client_analyse_packets import mcl_analyse_pkts_main
from meas_client_display_results import mcl_display_results_main
from collections import defaultdict
from datetime import date
import meas_client_global_const

# Globals
DEBUG = 1
port_to_app_map = defaultdict(list)
global dl_status


def mcl_download_app_data(debug):
    for app in app_list:
        print(str(port) + ":" + str(app) + '\n')
        port = mcl_start_download(debug, app)
        port_to_app_map[port] = app


def mcl_store_pkts(debug, pkts, sapp):
    from meas_client_utils import mcl_copy_file, mcl_make_dir
    # sfname = "D:\\Vinod\\Code\\Meas_client\\output_data\\pkts.pcap"
    sfname = os.path.join("output_data", "pkts.pcap")
    # sfname = os.path.abspath("output_data/pkts.pcap")
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        print("AOLEN = " + str(aolen))
        for i in app_opt:
            # dfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\" + str(app) + "_" + str(i) + "\\pkts.pcap"
            # dfname = "input_data/Pcap"
            dfname = os.path.join("input_data", "Pcap")
            if not os.path.exists(dfname):
                mcl_make_dir(dfname)
            dfname1 = str(app) + "_" + str(i)
            # dfname = dfname + "/" + str(app) + "_" + str(i)
            dfname = os.path.join(dfname, dfname1)
            if not os.path.exists(dfname):
                mcl_make_dir(dfname)
            dfname = os.path.join(dfname, "pkts.pcap")
            dfname = os.path.abspath(dfname)
            # wrpcap(fname,meas_client_global_const.sniff_pkts)
            print("Copying " + str(sfname) + " to " + str(dfname))
            # os.system("copy {0} {1}".format(sfname, dfname))
            mcl_copy_file(sfname, dfname)


def mcl_read_binary_data():
    from meas_client_utils import mcl_copy_file
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # sfname = "D:\\Vinod\\Code\\Meas_client\\output_data\\"+str(app) + "_" + str(i)
            sfname = os.path.join("output_data", str(apptype))
            sfname = os.path.abspath(sfname)
            # dfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\" + str(app) + "_" + str(i) + "\\" + \
            #         str(app) + "_" + str(i)
            # dfname = "input_data/Pcap/" + str(apptype) + "/" + str(apptype)
            dfname = os.path.join("input_data", "Pcap", str(apptype), str(apptype))
            # dfname = os.path.abspath(dfname)
            print("Copying " + str(sfname) + " to " + str(dfname))
            # os.system("copy {0} {1}".format(sfname, dfname))
            mcl_copy_file(sfname, dfname)


def mcl_app_handler(debug, app, sniffer, sniffer_p, typeid):
    try:
        # Start sniffing packets
        # dl_done.clear()
        # sniffer, sniffer_p = mcl_sniff_packets(debug,app)
        # Start downloading videos
        meas_client_global_const.dl_status_bmp = (meas_client_global_const.dl_status_bmp << 1) | 1
        port = mcl_start_download(debug, app, typeid)
    except KeyboardInterrupt:
        print("User interruption")

    meas_client_global_const.dl_status_bmp = meas_client_global_const.dl_status_bmp >> 1
    print("dl_status_bmp = " + str(meas_client_global_const.dl_status_bmp))
    print(str(port) + ":" + str(app) + '\n')
    meas_client_global_const.port_to_app_map[port] = str(app) + "_" + str(typeid)
    # print(port_to_app_map)
    # Store sniffed packets in pcap format
    if 0 == meas_client_global_const.dl_status_bmp:
        dl_done.set()
        # time.sleep(0.1)
        if sniffer is not None and sniffer_p is not None:
            pkts = mcl_get_pkts_from_sniffer(debug, sniffer_p, sniffer, None)
            mcl_store_pkts(debug, pkts, app)
        print("Download done ....")
        sniff_done.set()


def mcl_direct_download_handler_thread(debug, app, vid_link, sniffer, sniffer_p):
    # from meas_client_direct_downloader import mcl_download_media
    # t_sleep = mcl_download_media(debug, vid_link)
    t_sleep = 60*2
    time.sleep(t_sleep)
    print("Download complete")
    dl_done.set()
    pkts = mcl_get_pkts_from_sniffer(debug, sniffer_p, sniffer, None)
    mcl_store_pkts(debug, pkts, app)
    sniff_done.set()


def mcl_get_test_status(pstatus):
    if pstatus == 1:
        print("Used stored data for streaming")
        return "STORED"
    elif pstatus == 2:
        print("Original streaming server used through proxy")
        return "ORG_WP"
    elif pstatus == 0:
        print("No proxy server used")
        return "ORG_NP"
    elif pstatus == 3:
        print("Using standard browser/app with no vpn")
        return "ORG_NR_NVPN"
    elif pstatus == 4:
        print("Using standard browser/app with proxy/vpn")
        return "ORG_NR_WVPN"


def mcl_store_results(nw):
    import datetime
    import uuid
    import warnings
    from meas_client_utils import mcl_make_dir, mcl_move_file
    warnings.filterwarnings("ignore")
    today = date.today()
    now = datetime.datetime.now()
    print(str(today) + " " + str(now.hour) + " " + str(now.minute) + " " + str(now.second))
    dname = str(today) + "-" + str(now.hour) + "-" + str(now.minute) + "-" + str(now.second)
    print(dname)
    num_app = len(app_list)
    # print(num_app)
    dpath = "Meas_results"
    if not os.path.exists(dpath):
        mcl_make_dir(dpath)
    dpath1 = str(nw) + "_"
    dpath = os.path.join(dpath, dpath1)
    # dpath = "Meas_results/" + str(nw) + "-"
    """
    if use_proxy == 1:
        print("Proxy streaming server used")
        if use_stored_data == 1:
            print("Used stored data for streaming")
            dpath = dpath + "PROXY-STORED-"
        else:
            print("Original streaming server used")
            dpath = dpath + "PROXY-ORG-"
    else:
        print("No proxy server used")
        dpath = dpath + "ORG-"
    """
    if 1 == num_app:
        app = app_list.popitem()
        lptype = app[1]
        for i in lptype:
            pstatus = mcl_get_test_status(i)
            dpath = dpath + str(pstatus) + "-"
        dpath = dpath + str(app[0]) + "-"
    else:
        for app in app_list:
            lptype = app_list[app]
            print(lptype)
            for i in lptype:
                pstatus = mcl_get_test_status(i)
                if str(pstatus) not in dpath:
                    dpath = dpath + str(pstatus) + "-"
        if "NETFLIX" in app_list or "YOUTUBE" in app_list or "HOTSTAR" in app_list:
            dpath = dpath + "VID-COMP-"
        else:
            dpath = dpath + "AUD-COMP-"
    dpath = dpath + dname
    spath = os.path.join("output_data", "*")
    os.path.abspath(spath)
    os.path.abspath(dpath)
    print(dpath)
    print(spath)
    mcl_make_dir(dpath)
    # os.system("mkdir {0}".format(dpath))
    mcl_move_file(spath, dpath)
    # os.system("move {0} {1}".format(spath, dpath))


def mcl_direct_download_handler(debug, app, vid_link, sniffer, sniffer_p):
    dl_ready.clear()
    print("Downloading " + str(vid_link))
    app_th = threading.Thread(target=mcl_direct_download_handler_thread,
                              args=(debug, app, vid_link, sniffer, sniffer_p))
    app_th.start()
    while True:
        try:
            if False == sniff_done.is_set():
                time.sleep(30)
            else:
                print("Exiting download module ...")
                # time.sleep(0.1)
                break;
        except KeyboardInterrupt:
            print("Exiting download module ...")
            dl_done.set()
            pkts = mcl_get_pkts_from_sniffer(debug, sniffer_p, sniffer, None)
            mcl_store_pkts(debug, pkts, app)
            sniff_done.set()
            break;


def mcl_read_app_data():
    import os
    from meas_client_utils import mcl_delete_file
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            p_app_data = app_data[apptype]
            # fname = "output_data/" + str(apptype) + "_data.txt"
            fname = os.path.join("output_data", str(apptype) + "_data.txt")
            if os.path.exists(fname):
                mcl_delete_file(fname)
                # os.system("del {0}".format(fname))
            fp = open(fname, "a")
            # dfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\" + str(apptype) + "\\" + str(
            #    apptype) + "_data.txt"
            # dfname = "input_data/Pcap/" + str(apptype) + "/" + str(apptype) + "_data.txt"
            dfname = os.path.join("input_data", "Pcap", str(apptype), str(apptype) + "_data.txt")
            # dfname = os.path.abspath(dfname)
            if os.path.exists(dfname):
                mcl_delete_file(dfname)
                # os.system("del {0}".format(dfname))
            print("App data file:" + str(dfname))
            dfp = open(dfname, "a")
            for data in p_app_data:
                output_data = str(data.dtime) + "#" + str(data.dlen) + "\n"
                fp.write(output_data)
                dfp.write(output_data)
            fp.close()
            dfp.close()


def mcl_read_burst_data():
    import os
    from meas_client_utils import mcl_delete_file
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            b_app_data = burst_data[apptype]
            # print(b_app_data)
            # fname = "output_data/" + str(apptype) + "_bdata.txt"
            fname = os.path.join("output_data/", str(apptype) + "_bdata.txt")
            # os.path.abspath(fname)
            if os.path.exists(fname):
                mcl_delete_file(fname)
                # os.system("del {0}".format(fname))
            fp = open(fname, "a")
            # dfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\" + str(apptype) + "\\" + str(
            #    apptype) + "_bdata.txt"
            # dfname = "input_data/Pcap/" + str(apptype) + "/" + str(apptype) + "_bdata.txt"
            dfname = os.path.join("input_data", "Pcap", str(apptype),  str(apptype) + "_bdata.txt")
            # os.path.abspath(dfname)
            if os.path.exists(dfname):
                mcl_delete_file(dfname)
                # os.system("del {0}".format(dfname))
            print("App data file:" + str(dfname))
            dfp = open(dfname, "a")
            for data in b_app_data:
                output_data = str(data[0]) + "#" + str(data[1]) + "\n"
                fp.write(output_data)
                dfp.write(output_data)
            fp.close()
            dfp.close()


def mcl_process_single_report():
    from meas_client_process_report import mcl_process_report
    td_status = {}
    rname = input("Please enter name of report: ")
    if not rname:
        # rname = "80f7feb9-9f2a-40ff-9015-79638a3aad28-191222231555+0530"
        # rname = "4fb3e22f-985b-406d-8a48-1e29fd82b061-200615182802+0530"
        # rname = "fdc50609-e7ee-47f3-952e-8902548751af-210517025814+0530" # IAT issue
        rname = "5e70b161-eed0-4f2a-b31c-bb3a398ce055-210520211435+0530" # TD Case
    report = "./input_data/Reports/"+rname
    # mcl_process_report("Report/e796a606-0f0c-4942-b66d-fa118acfd051-200104032019+0530")
    app_td_status, td, t_time, td_detect = mcl_process_report(report, "")
    # print(app_td_status)
    #for app in app_td_status:
    #    if app not in td_status:
    #        td_status[app] = [0, 0]
    #    td_thr = app_td_status[app][0]
    #    td_range = app_td_status[app][1]
    #    if td_thr:
    #        td_status[app][0] += 1
    #    if td_range:
    #        td_status[app][1] += 1
    #print(td_status)
    print("User Name : " + str(meas_client_global_const.user_name))
    print("User Info : " + str(meas_client_global_const.user_info))
    print("User result : " + str(meas_client_global_const.user_result))
    x = input()


def mcl_seg_th_data(l_data):
    r_data = {}
    for i in range (0, 6):
        r_data[i] = 0
    for data in l_data:
        if data == 0:
            r_data[0] += 1
        elif 0 < data <= 1:
            r_data[1] += 1
        elif 1 < data <= 2:
            r_data[2] += 1
        elif 2 < data <= 3:
            r_data[3] += 1
        elif 3 < data <= 4:
            r_data[4] += 1
        elif 4 < data <= 5:
            r_data[5] += 1
    return r_data


def mcl_plot_th_data(app):
    from meas_client_utils import mcl_draw_bar_chart
    l_data = th_per_app["YOUTUBE_1"]
    th_data = mcl_seg_th_data(th_per_app[app])
    print(th_data)
    fname = "output_data/" + str(app) + "_app_th.png"
    mcl_draw_bar_chart(th_data, None, None, fname)


def mcl_plot_slot_th_diff():
    from meas_client_utils import mcl_plot_data
    # print(th_per_app["YOUTUBE_1"].sort())
    mcl_plot_data(th_per_app["YOUTUBE_1"], 'Index', 'Per slot throughput difference (Mbps)', 'output_data/app_th.png')


def mcl_plot_num_of_users():
    from meas_client_global_const import num_installs, installs
    print("Num installs = " + str(len(installs)))
    print(installs)


def mcl_plot_results():
    # Plot per slot throughput difference
    # mcl_plot_slot_th_diff()
    # Plot throughput in bar chart as number of occurrences of throughput
    for app in app_list:
        atype = str(app) + "_1"
        # mcl_plot_th_data(atype)
    mcl_plot_num_of_users()


def mcl_day_add_new_results(dp, sp):
    #print("DP : " + str(dp))
    #print("SP : " + str(sp))
    found = False
    for ct in sp:
        if ct in dp:
            ct_info = dp[ct]
            dp[ct] = meas_client_global_const.user_result
            found = True
            break
    if not found:
        for ct in sp:
            dp[ct] = meas_client_global_const.user_result
    #print("DP : " + str(dp))
    return dp


def mcl_isp_add_new_results(dp, sp):
    #print("DP : " + str(dp))
    #print("SP : " + str(sp))
    found = False
    for day in sp:
        if day in dp:
            day_info = dp[day]
            day_info = mcl_day_add_new_results(day_info, sp[day])
            dp[day] = day_info
            found = True
            break
    if not found:
        for day in sp:
            dp[day] = sp[day]
    #print("DP : " + str(dp))
    return dp


def mcl_loc_add_new_results(dp, sp):
    #print("DP : " + str(dp))
    #print("SP : " + str(sp))
    found = False
    for isp in sp:
        if isp in dp:
            isp_info = dp[isp]
            isp_info = mcl_isp_add_new_results(isp_info, sp[isp])
            dp[isp] = isp_info
            found = True
            break
    if not found:
        for isp in sp:
            dp[isp] = sp[isp]
    #print("DP : " + str(dp))
    return dp


def mcl_user_add_new_results(dp, sp):
    #print("DP : " + str(dp))
    #print("SP : " + str(sp))
    found  = False
    for loc in sp:
        if loc in dp:
            loc_info = dp[loc]
            loc_info = mcl_loc_add_new_results(loc_info, sp[loc])
            dp[loc] = loc_info
            found = True
            break
    if not found:
        for day in sp:
            dp[loc] = sp[loc]
    #print("DP : " + str(dp))
    return dp


def mcl_update_user_results(user_info, user_result):
    #print("User Info in : "+str(user_info))
    #print("User results in : "+str(user_result))
    for loc in user_info:
        for isp in user_info[loc]:
            for day in user_info[loc][isp]:
                for ct in user_info[loc][isp][day]:
                    user_info[loc][isp][day][ct] = user_result
    #print("User Info in : "+str(user_info))
    return user_info


def mcl_update_results(t_time, td_detect):
    auinfo = []
    user_name = meas_client_global_const.user_name
    user_info = meas_client_global_const.user_info
    user_result = meas_client_global_const.user_result
    #print("In user result = " + str(user_result))
    u_info = meas_client_global_const.u_info
    user_info = mcl_update_user_results(user_info, user_result)
    if user_name in u_info:
        # cu_data = u_info[user_name]
        # cu_data = mcl_user_add_new_results(cu_data, user_info)
        # user_name = user_name.split("_")[1] + 1
        cu_data = user_info
    else:
        # user_name = user_name + "_0"
        cu_data = user_info
    u_info[user_name] = [cu_data, t_time, td_detect]


def mcl_get_gen_stats(res):
    usrs = []
    locs = []
    isps = []
    tcs = 0
    for user in res:
        if user not in usrs:
            usrs.append(user)
        for loc in res[user]:
            if "NA" in loc or "Permission denied" in loc:
                continue
            if loc not in locs:
                locs.append(loc)
            for isp in res[user][loc]:
                if "192." in isp or "127." in isp or "Local" in isp or "null" in isp:
                    continue
                if isp not in isps:
                    isps.append(isp)
        tcs += 1
    print("Total logs = " + str(tcs))
    print("Total countries = "+str(len(locs)))
    print("Countries = "+str(locs))
    print("Total ISPs = "+str(len(isps)))
    print("ISPs = "+str(isps))


def mcl_gen_comb_td_results(res):
    td = 0
    ntd = 0
    bn = 0
    itd = {}
    atd = {}
    iatd = {}
    aitd = {}
    fname = "./output_data/td_res.txt"
    fp = open(fname, "a")
    for user in res:
        for loc in res[user]:
            if "NA" in loc or "Permission denied" in loc:
                continue
            for isp in res[user][loc]:
                if "192." in isp or "127." in isp or "Local" in isp or "null" in isp:
                    continue
                if isp not in iatd:
                    iatd[isp] = {}
                    itd[isp] = [0, 0, 0]
                for day in res[user][loc][isp]:
                    for ctime in res[user][loc][isp][day]:
                        for app in res[user][loc][isp][day][ctime]:
                            if app not in atd:
                                atd[app] = [0, 0, 0]
                            if app not in iatd[isp]:
                                iatd[isp][app] = [0, 0, 0]
                            if app not in aitd:
                                aitd[app] = {}
                            if isp not in aitd[app]:
                                aitd[app][isp] = [0, 0, 0]
                            tds = res[user][loc][isp][day][ctime][app][0]
                            if tds == "TD":
                                td += 1
                                itd[isp][0] += 1
                                atd[app][0] += 1
                                iatd[isp][app][0] += 1
                                aitd[app][isp][0] += 2
                            elif tds == "No-TD":
                                ntd += 1
                                itd[isp][1] += 1
                                atd[app][1] += 1
                                iatd[isp][app][1] += 1
                                aitd[app][isp][1] += 2
                            elif tds == "Bad-Network":
                                bn += 1
                                itd[isp][2] += 1
                                atd[app][2] += 1
                                iatd[isp][app][2] += 1
                                aitd[app][isp][2] += 2
    output_data = "TD detected = " + str(td) + "\n"
    print(output_data)
    fp.write(output_data)
    output_data = "No-TD detected = " + str(ntd) + "\n"
    print(output_data)
    fp.write(output_data)
    output_data =  "Bad Network detected = " + str(bn) + "\n"
    print(output_data)
    fp.write(output_data)
    output_data = "Application TD status : " + str(atd) + "\n"
    print(output_data)
    fp.write(output_data)
    output_data = "ISP-Application TD status : " + str(iatd) + "\n"
    print(output_data)
    fp.write(output_data)
    output_data = "Application-ISP TD status : " + str(aitd) + "\n"
    print(output_data)
    fp.write(output_data)
    output_data = "ISP TD status : " + str(itd) + "\n"
    print(output_data)
    fp.write(output_data)
    fp.close()
    return atd, iatd, aitd, itd


def mcl_gen_results(res):
    #import json
    #print(res)
    #res1 = json.loads(res)
    mcl_get_gen_stats(res)
    atd, iatd, aitd, itd = mcl_gen_comb_td_results(res)
    return [atd, iatd, aitd, itd]


def mcl_plot_bar_chart(p, data, x_pos, col, width, bottom):
    print("Shwoing bar chart")


def mcl_plot_app_data(adata):
    print("Showing app data")
    for isp in adata:
        print(str(isp))
        idata = adata[isp]
        # mcl_plot_isp_data(idata)


def mcl_plot_aitd(aitd):
    import numpy as np
    import matplotlib.pyplot as p
    alabel = []
    app_name_list = ["HOTSTAR", "NETFLIX", "YOUTUBE", "PRIMEVIDEO", "GAANA", "SPOTIFY", "SAAVN", "WYNK"]
    p.cla()
    print(str(aitd))
    for data in aitd:
        alabel.append(data)
    num_app = len(alabel)
    X = np.arange(num_app)
    for app in aitd:
        aname = app.split("_")[0]
        if aname not in app_name_list:
            continue
        print(aname)
        adata = aitd[app]
        mcl_plot_app_data(X, adata)


def mcl_get_per_app_td(td_data):
    td = []
    ntd = []
    bnw = []
    if None is td_data:
        td = [1, 1, 1, 1, 1, 1, 1, 1]
        td = [1, 1, 1, 1, 1, 1, 1, 1]
    else:
        for data in td_data:
            td.append(td_data[data][0])
            ntd.append(td_data[data][1])
            bnw.append(td_data[data][2])
    return td, ntd, bnw


def mcl_plot_isp_data(p, X, x_pos, data, label):
    atd_td, atd_ntd, atd_bnw = mcl_get_per_app_td(data)
    if label:
        p.bar(X + x_pos, atd_td, color='r', width=0.1, label="TD detected")
        p.bar(X + x_pos, atd_ntd, color='g', width=0.1, bottom=atd_td, label="No TD detected")
        p.bar(X + x_pos, atd_bnw, color='b', width=0.1, bottom=atd_ntd, label="Bad Network")
    else:
        p.bar(X + x_pos, atd_td, color='r', width=0.1)
        p.bar(X + x_pos, atd_ntd, color='g', width=0.1, bottom=atd_td)
        p.bar(X + x_pos, atd_bnw, color='b', width=0.1, bottom=atd_ntd)
    #p.plot()
    #p.show()


def mcl_plot_iatd(iatd):
    import numpy as np
    import matplotlib.pyplot as p
    app_name_list = ["HOTSTAR", "NETFLIX", "YOUTUBE", "PRIMEVIDEO", "GAANA", "SPOTIFY", "SAAVN", "WYNK"]
    p.cla()
    print(str(iatd))
    num_app = len(app_name_list)
    X = np.arange(num_app)
    x = range(num_app)
    data = {}
    x_pos = 0
    lab = True
    for isp in iatd:
        idata = iatd[isp]
        for app in app_name_list:
            aname = app + str("_1")
            if aname in idata:
                data[app] = idata[aname]
            else:
                data[app] = [0, 0, 0]
        mcl_plot_isp_data(p, X, x_pos, data, lab)
        lab = False
        x_pos += 0.1
    p.plot()
    p.grid(linestyle='--', linewidth=0.25)
    p.xlabel('Services', fontsize=15)
    p.ylabel('Count', fontsize=15)
    p.xticks(x, app_name_list)
    p.tick_params(width=2, length=5, labelsize=6)
    ax = p.subplot(111)
    ax.legend()
    fname = "output_data/app_isp_td_status.png"
    p.savefig(fname, dpi=600)
    p.show()
    p.cla()



def mcl_plot_gen_results(res):
    print("Showing results ")
    atd = res[0]
    iatd = res[1]
    aitd = res[2]
    itd = [3]
    # mcl_plot_aitd(aitd)
    mcl_plot_iatd(iatd)


def mcl_get_raw_res():
    res = None
    fname = "input_data/td_raw_res.txt"
    fp = open(fname, "r")
    res = fp.read()
    # print(res)
    return res


def mcl_get_td_analysis(res):
    if None is res:
        res = mcl_get_raw_res()
    res = mcl_gen_results(res)
    # mcl_plot_gen_results(res)


def mcl_get_nl_analysis():
    import collections
    fname = "./input_data/nl_data_new.txt"
    nl_fp = open(fname, "r")
    nl_data = nl_fp.read().split(",")
    # print("NL Data : " + str(nl_data))
    nl_res = {}
    nl_count_l = 0
    for nl in nl_data:
        if nl == "":
            continue
        nl = int(nl)
        # print(str(nl_count_l) + ":" + str(nl))
        if nl in nl_res:
            nl_res[nl] += 1
        else:
            nl_res[nl] = 1
        nl_count_l += 1
    # nl_res[100] = 0
    nl_res = sorted(nl_res.items())
    # print("NL Res : " + str(nl_res))
    t_nl = 0
    nl_cdf = []
    nl_cdf_c = []
    nl_th = []
    for nl in nl_res:
        # print("NL = " + str(nl[0]))
        t_nl += nl[1]
        nl_cdf.append(t_nl/nl_count_l)
        nl_cdf_c.append(nl[0])
        nl_th.append(0.98)
        # print("t_nl =  " + str(t_nl))
    print("NL Count : " + str(nl_count_l))
    pcolor = 'blue'
    plt.plot(nl_cdf_c, nl_th, markersize=20, linewidth=2, color='red')
    plt.plot(nl_cdf_c, nl_cdf, markersize=20, linewidth=2, color=pcolor)
    plt.xlabel('% low throughput slots', fontsize=12)
    plt.ylabel('CDF', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/nlextentcdf.png')
    plt.show()
    return  nl_cdf_c, nl_cdf


def mcl_get_nl_perslot_analysis():
    import sys
    import collections
    fname = "./input_data/nl_ps_data.txt"
    nl_fp = open(fname, "r")
    nl_data = nl_fp.read().split(",")
    print("NL Data : " + str(nl_data))
    nl_res = {}
    nl_count_l = 0
    nl_count = 0
    for nl in nl_data:
        if nl == "":
            continue
        nl = nl.split(":")
        nl_slot = int(nl[0].replace("{", ""))
        nl_count = int(nl[1].replace("}", ""))
        if nl_slot > 60:
            continue
        nl_res[nl_slot] = nl_count
        nl_count_l += nl_count
    nl_res = collections.OrderedDict(sorted(nl_res.items()))
    print(" nl_res : " + str(nl_res) + " NL Count : " + str(nl_count_l))
    t_nl = 0
    nl_cdf = []
    nl_cdf_c = []
    nl_th = []
    for nl in nl_res:
        # print("NL = " + str(nl_res[nl]))
        t_nl = nl_res[nl]
        nl_cdf.append((t_nl/nl_count_l))
        nl_cdf_c.append(nl)
        # nl_th.append(0.98)
        # print("t_nl =  " + str(t_nl) + "P = " + str(t_nl/nl_count_l))
    print("Min TS : " + str(min_num_ts))
    pcolor = 'blue'
    # plt.plot(nl_cdf_c, nl_th, markersize=20, linewidth=2, color='red')
    plt.plot(nl_cdf_c, nl_cdf, markersize=20, linewidth=2, color=pcolor)
    plt.xlabel('Slot index', fontsize=12)
    plt.ylabel('low throughput slots pdf', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/pslotnlpdf.png')
    plt.show()
    return  nl_cdf_c, nl_cdf


def mcl_analyse_results(res):
    isps = []
    print("Analysing report results")
    # Get n_l time range analysis
    # nl_cdf_idx, nl_cdf = mcl_get_nl_analysis()
    # print("NL CDF Count : " + str(nl_cdf_idx))
    # print("NL CDF = " + str(nl_cdf))

    # Get per slot n_l analysis
    # mcl_get_nl_perslot_analysis()

    # Get TD analysis
    mcl_get_td_analysis(res)


def mcl_process_report_bunch(nw):
    import os
    from meas_client_process_report import mcl_process_report
    store = True
    td_status = {}
    th_data = []
    i = 0
    gen_res = True
    if gen_res:
        meas_client_global_const.u_info = {}
        rdir = input("Please enter report directory: ")
        if not rdir or None is rdir:
            # rdir = "./Report/" + nw + "/Logs/"
            rdir = "./input_data/Reports/"
            # rdir = "./input_data/R/"
        print("rdir : " + str(rdir))
        fnames = os.listdir(rdir)
        if len(fnames) == 0:
            print("No report to analyse....Exiting")
            store = False
        else:
            rcount = 0
            for fname in fnames:
                if "." in fname:
                    continue
                rfname = rdir + fname
                print(rfname)
                app_td_status, td, t_time, td_detect = mcl_process_report(rfname, "")
                #print("APP TD STATUS = "+str(app_td_status))
                if app_td_status is None or td is None:
                    continue
                rcount += 1
                print(str(rcount) + " : " + rfname)
                #for app in app_td_status:
                #    if app not in td_status:
                #        td_status[app] = [0, 0]
                #    td_thr = app_td_status[app][0]
                #    td_range = app_td_status[app][1]
                #    if td_thr:
                #        td_status[app][0] += 1
                #    if td_range:
                #        td_status[app][1] += 1
                #print(td_status)
                mcl_update_results(t_time, td_detect)
                #print("User Info post : " + str(u_info))
                i+=1
                #x = input()
    fname = "output_data/td_raw_res.txt"
    fp = open(fname, "a")
    fp.write(str(meas_client_global_const.u_info))
    fp.close()
    # Enable to analyse results (per-ISP-per-app TD) - Imp *******
    #mcl_analyse_results(meas_client_global_const.u_info)
    #mcl_plot_results()
    print("Total network logs = "+str(i))
    return store


def mcl_process_report_bunch_dy(nw, ththr, slthr):
    import os
    from meas_client_process_report import mcl_process_report_dy
    store = True
    td_status = {}
    th_data = []
    i = 0
    st = 2.5
    gen_res = True
    if gen_res:
        meas_client_global_const.u_info = {}
        rdir = "./input_data/Reports/"
        print("rdir : " + str(rdir))
        fnames = os.listdir(rdir)
        if len(fnames) == 0:
            print("No report to analyse....Exiting")
            store = False
        else:
            rcount = 0
            for fname in fnames:
                if "." in fname:
                    continue
                rfname = rdir + fname
                print(rfname)
                app_td_status, td, t_time, td_detect = mcl_process_report_dy(rfname, "", ththr, slthr, st)
                app_td_status, td, t_time, td_detect = mcl_process_report_dy(rfname, "", ththr, slthr, st)
                #print("APP TD STATUS = "+str(app_td_status))
                if app_td_status is None or td is None:
                    continue
                rcount += 1
                print(str(rcount) + " : " + rfname)
                #for app in app_td_status:
                #    if app not in td_status:
                #        td_status[app] = [0, 0]
                #    td_thr = app_td_status[app][0]
                #    td_range = app_td_status[app][1]
                #    if td_thr:
                #        td_status[app][0] += 1
                #    if td_range:
                #        td_status[app][1] += 1
                #print(td_status)
                mcl_update_results(t_time, td_detect)
                #print("User Info post : " + str(u_info))
                i+=1
                #x = input()
    fname = "output_data/td_raw_res.txt"
    fp = open(fname, "w")
    fp.write(str(meas_client_global_const.u_info))
    fp.close()
    # Enable to analyse results (per-ISP-per-app TD) - Imp *******
    #mcl_analyse_results(meas_client_global_const.u_info)
    #mcl_plot_results()
    print("Total network logs = "+str(i))
    return store

def mcl_get_app_server_info():
    import select
    from meas_client_utils import mcl_get_ssl_socket
    timeout = 1
    app_server = "0.0.0.0"
    print("Getting server information")
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
    # Connect to Webserver
    print("Connected to webserer ")
    s.connect((webserver, webport))
    # Upgrade to SSL
    s = mcl_get_ssl_socket(s, webserver)
    # Send request to webserver
    # sdata = clientId.encode('utf-8')
    print("Established TLS connection")
    sdata = clientId + ":" + "ASIA"
    sdata = sdata.encode('utf-8')
    s.sendall(sdata)
    print("Request sent to Webserver")
    # Wait for response from webserver
    while True:
        try:
            while True:
                try:
                    rs, ws, es = select.select([s], [], [], timeout)
                    if s in rs:
                        rstatus = "SUCCESS"
                        break
                except KeyboardInterrupt:
                    rstatus = "ERROR"
                    break
            print("r: " + str(rs))
            print("w: " + str(ws))
            print("e: " + str(es))
            if rstatus == "SUCCESS":
                rdata = ""
                while "" == rdata:
                    rdata = s.recv(8192*4).decode('utf-8')
                print("Received data = " + str(rdata))
                rdata = rdata.split()
                status = rdata[0]
                if "RUNNING" == status:
                    app_server = rdata[1]
                    app_port = rdata[2]
                    print("App server = " + str(app_server) + ":" + str(app_port))
                    break
            else:
                break
        except KeyboardInterrupt:
            rstatus = "ERROR"
            break
    # Extract app_server
    print("Exiting app_server_info")
    return status, app_server, app_port


def mcl_main(nw, comm, fpath):
    import datetime as datetime
    store = True
    pkts = None
    sniff_done.clear()
    fname = 'output_data/mcl.txt'
    #fp = mcl_fopen(DEBUG, fname, "w", "NA")
    output_data = "Measurement Client"
    #mcl_fwrite(DEBUG, fp, output_data)
    #mcl_fclose(fp)
    mcl_sniff_var()
    # otime = datetime.now()
    if comm == "SNIFF":
        print("Only sniffing packets...")
        # Start sniffing packets
        dl_done.clear()
        sniffer, sniffer_p = mcl_sniff_packets(DEBUG, "")
        while True:
            try:
                time.sleep(30)
            except KeyboardInterrupt:
                print("User interruption")
                debug = 1
                # Complete sniffing
                dl_done.set()
                pkts = mcl_get_pkts_from_sniffer(debug, sniffer_p, sniffer, None)
                print("Sniffing done ....")
                break
    if comm == "DD":
        print("Starting direct download mode ")
        # Start sniffing packets
        dl_done.clear()
        sniffer, sniffer_p = mcl_sniff_packets(DEBUG, "")
        # Start download
        vid_link = input("Please enter video link: ")
        app = "YOUTUBE"
        if None == vid_link:
            vid_link = "https://www.youtube.com/watch?v=oYXPfNuTb88"
        mcl_direct_download_handler(DEBUG, app, vid_link, sniffer, sniffer_p)
    if comm == "ALL" or comm == "DOWNLOAD":
        import meas_client_global_const
        status = None
        app_server = None
        app_port = None
        sniffer = None
        sniffer_p = None
        # Start sniffing packets
        dl_done.clear()
        # print("Start Sniffing")
        sniffer, sniffer_p = mcl_sniff_packets(DEBUG, "")
        # Get application server
        if None is not webserver:
            status, app_server, app_port = mcl_get_app_server_info()
        else:
            status = "SUCCESS"
            app_server = '192.168.0.22'
            app_port = 8086
        if "ERROR" == status:
            print("Application server error")
            return
        meas_client_global_const.proxy = app_server
        meas_client_global_const.proxy_port = app_port
        # print("In main appserver = " + str(app_server))
        # print("In main Proxy = " + str(meas_client_global_const.proxy) + ":" + str(meas_client_global_const.proxy_port))
        # Start download
        dl_ready.clear()
        for app in app_list:
            app_opt = app_list[app]
            aolen = len(app_opt)
            print("AOLEN = " + str(aolen))
            for i in app_opt:
                # sys.exit(0)
                print("Downloading " + str(app) + "_" + str(i))
                app_th = threading.Thread(target=mcl_app_handler, args=(DEBUG, app, sniffer, sniffer_p, i))
                app_th.start()
        while True:
            try:
                if False == sniff_done.is_set():
                    time.sleep(30)
                else:
                    print("Exiting download module ...")
                    mcl_read_app_data()
                    mcl_read_burst_data()
                    mcl_read_binary_data()
                    # time.sleep(0.1)
                    break
            except KeyboardInterrupt:
                print("Exiting download module ...")
                mcl_read_app_data()
                mcl_read_burst_data()
                mcl_read_binary_data()
                # time.sleep(0.1)
                break
    if comm == "REPORT":
        mode = input("Number of reports (SINGLE/BUNCH)")
        if "SINGLE" == mode:
            mcl_process_single_report()
            #mcl_plot_num_of_users()
        else:
            ththr = 1000000
            slthr = 0.2
            store = mcl_process_report_bunch_dy(nw, ththr, slthr)
            sfname = "output_data/td_raw_res.txt"
            dfname = "input_data/td_raw_res.txt"
            mcl_copy_file(sfname, dfname)
            #store = mcl_process_report_bunch(nw)
    if comm == "AR":
        from meas_client_analyse_results import mcl_analyse_results
        mcl_analyse_results(None)
    if comm == "ALL" or comm == "ANALYSE" or comm == "DD":
        # Analyse sniffed packets for performance
        import meas_client_global_const
        if meas_client_global_const.sniff_pkts is None:
            debug = 1
            # host = '192.168.225.118' #Jio
            # host = "192.168.0.19"  # Hathway
            host = "192.168.43.28" # Vodafone, Airtel
            # host = "10.119.2.18" # Raigad
            # host = '10.119.31.31' #IEOR-PhD-Lab
            # host = '10.119.21.55'
            # host = '10.119.21.38'
            port_to_app_map = {56561: "HOTSTAR_1",
                               56083: "NETFLIX_1",
                               64954: "YOUTUBE_1",
                               58611: "YOUTUBE_5",
                               64953: "PRIMEVIDEO_1",
                               50031: "HOTSTAR_2",
                               61531: "NETFLIX_2",
                               # 61490: "YOUTUBE_2",
                               61533: "YOUTUBE_2",
                               63250: "PRIMEVIDEO_2",
                               63251: "HOTSTAR_0",
                               63252: "NETFLIX_0",
                               50873: "VOID",
                               50873: "VOID",
                               64822: "YOUTUBE_0",
                               63250: "PRIMEVIDEO_0",
                               65508: "HOTSTAR_3",
                               50130: "NETFLIX_3",
                               64843: "YOUTUBE_3",
                               49808: "PRIMEVIDEO_3",
                               65521: "HOTSTAR_4",
                               50167: "NETFLIX_4",
                               50043: "YOUTUBE_4",
                               49823: "PRIMEVIDEO_4",
                               50873: "SPOTIFY",
                               60381: "WYNK_1",
                               61159: "GAANA.COM",
                               50400: "GAANA.COM_1",
                               61426: "SAAVN",
                               54927: "FILE_1"}
        else:
            host = None
            port_to_app_map = meas_client_global_const.port_to_app_map
        mcl_analyse_pkts_main(DEBUG, pkts, port_to_app_map, host)
    if comm == "SHOW":
        mcl_display_results_main(comm, fpath)

    if store == True:
        mcl_store_results(nw)
    # ctime = datetime.now()
    # tdiff = ctime - ctime
    # tdfif = tdiff.allmiliseconds()
    # print(tdiff)


if __name__ == '__main__':
    nw = input("ISP (e.g. AIRTEL)")
    comm = input("SNIFF/DD/DOWNLOAD/ANALYSE/REPORT/ANALYZE_REPORT/SHOW/ALL:")
    alen = len(sys.argv)
    if 2 > alen:
        fpath = 'output_data'
    else:
        fpath = sys.argv[1]
    mcl_main(nw, comm, fpath)
