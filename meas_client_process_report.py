# -*- coding : utf-8 -*-
from meas_client_utils import *
from meas_client_global_const import *
import meas_client_global_const


def mcl_get_report_data(report):
    fp = open(report)
    rdata = fp.read()
    fp.close()
    return str(rdata)


test_list = {"HOTSTAR": 1,
             "NETFLIX": 2,
             "YOUTUBE": 3,
             "PRIMEVIDEO": 4}


def mcl_gen_user_isp_loc_db(data):
    #print("Data = "+str(data))
    isp_data = {}
    loc_data = {}
    data = data.split(":")
    # print("Instance data split : " + str(data))
    dt_info, t_info = mcl_get_tdata(data[0])
    if len(data) > 1:
        isp_data[data[1]] = dt_info
    else:
        isp_data["None"] = dt_info
    #print("ISP info:" +str(isp_data))
    if len(data) > 2:
        if "Hathway" in data[1]:
            data[2] = 'in'
        loc_data[data[2]] = isp_data
    else:
        loc_data["None"] = isp_data
    #print("Loc info:" + str(loc_data))
    return loc_data, t_info


def mcl_get_app_data_list(rdata, uid_idx):
    app_data_list = {}
    apps = []
    dsize = 0
    if "ClientId" not in rdata:
        return None, None
    if "Instance" not in rdata:
        return None, None
    apps_data = rdata.split("App :")
    i = 0
    for adata in apps_data:
        # print("Adata = " + adata)
        if "\\n" in adata:
            oapp_name = adata.split("\\n")[0]
            # aname = app_name + "\\n"
        else:
            oapp_name = adata.split("\n")[0]
            # aname = app_name+"\n"
        # print("Oappname =" + oapp_name)
        app_name = oapp_name.split(":")
        if dsize < 20000000:
            if len(app_name) > 1:
                # print("dsize data : " + str(app_name[1]))
                dsize = app_name[1]
                if dsize is not "":
                    dsize = int(dsize)
                else:
                    dsize = 20000000
            else:
                dsize = 20000000
        # print("Data size = " + str(dsize))
        # print("app_name" + str(app_name))
        if len(app_name) > 1:
            aname = app_name[0]
        else:
            aname = app_name[0]
        if "REPORT" in oapp_name:
            # print("Continuing for " + aname)
            continue
        if "ClientId" in adata:
            # print("Breaking for " + aname)
            rdata = adata.split("ClientId:")[1].split("\n")[0].split("-")
            meas_client_global_const.user_name = ""
            if rdata is not None:
                for data in rdata:
                    # meas_client_global_const.user_name = rdata[0] + rdata[1] + rdata[2] + rdata[3]
                    if data is not None:
                        meas_client_global_const.user_name += data
            meas_client_global_const.user_name += "-"
            meas_client_global_const.user_name += uid_idx
            # print("User name : "+str(meas_client_global_const.user_name))
        if "Instance" in adata:
            #print("Breaking for " + aname)
            rdata = adata.split("Instance:")[1].split("\n")[0]
            #print("Instance rdata = "+str(rdata))
            user_info, data = mcl_gen_user_isp_loc_db(rdata)
            meas_client_global_const.user_info = user_info
            # u_info[meas_client_global_const.user_name] = user_info
            # print("u_info = "+str(u_info))
            # break
        # print(app_name[2])
        data = adata.split(oapp_name)[1]
        data = data.replace("\\n", "\n")
        data = data.replace("\'", "")
        # print(data)
        if len(app_name) > 1:
            # print(app_name)
            ldata = [data, app_name[1], app_name[2]]
        else:
            ldata = [data, 0, 0]
        # print("ldata = " + str(ldata))
        # x = input()
        app_data_list[aname] = ldata
        apps.append(aname)
        # print("adata = "+str(app_data_list[aname]))
        # print("aname = "+str(aname))
        # x = input()
        i += 1
    # print(app_data_list)
    # print(apps)
    return dsize, apps, app_data_list


def mcl_store_app_data(apps, rdata):
    for app in apps:
        adata = apps[app]
        fname = "input_data/pcap/" + str(app) + "_1/" +app+"_1_bdata.txt"
        fp = open(fname, "w")
        fp.write(adata)


def mcl_check_hsdata():
    fname = "input_data/pcap/HOTSTAR_1/HOTSTAR_1_bdata.txt"
    fp = open(fname, "r")
    rdata = fp.read()
    rdata = rdata.split("\n")
    # print(rdata[0])


def mcl_calc_app_runavg_th(fp, adata):
    import re
    rt = 0
    pd = 0
    ct = 0
    tdiff = 0
    pcount = 0
    pth = []
    pindex = []
    th = 0
    adata = adata.split("\n")
    for data in adata:
        if "Instance" in data or "ClientId" in data:
            continue
        p = data.split(":")
        # print(p)
        if len(p) < 2:
            continue
        dtime = p[1]
        dlen = int(p[2])
        output_data = str(dtime) + ' ' + str(dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = dtime
        exp = int(ct.split("E")[1])
        mul = 10**exp
        ct = ct.replace("\'", "")
        ct = float(re.split(r"E\d+", ct)[0])
        ct = ct * mul
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if ct == rt:
            continue
        tdiff = ct - rt
        pd = pd + dlen * 8
        th = pd / (tdiff/1000)  # Nanosecond to millisecond conversion
        pcount += 1
        pth.append(th)
        pindex.append(pcount)
        output_data = str(pcount) + ' ' + str(dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
        ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    return pindex, pth


def mcl_calc_runavg_th(apps, app_data_list):
    from matplotlib import pyplot as plt
    b_th_info = {}
    for app in apps:
        apptype = str(app) + "_1"
        # print(apptype)
        adata = app_data_list[app]
        fname = "output_data/pbrath_rep_" + str(apptype) + ".txt"
        afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
        pindex, pth = mcl_calc_app_runavg_th(afp, adata)
        b_th_info[app] = pth.copy()
        b_th_info[app] = b_th_info[app].pop()
        pcolor = app_to_color_map[apptype]
        applabel = apptype + "_STORED"
        plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
    plt.xlabel('Burst number', fontsize=12)
    plt.ylabel('Cumulative Burst Throughput(bps)', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    # plt.savefig('output_data/rabth_rep.png')
    # plt.show()
    return b_th_info


def mcl_detect_rep_nnvd (fp, apps, bth_info, tapp):
    tdiff_norm = 0
    tr_status = "Traffic differentiation not detected"
    th = bth_info[tapp]
    # print("Test app th = "+str(th))
    max_th = th
    for app in apps:
        cth = bth_info[app]
        if max_th < cth:
            max_th = cth
    if th > max_th:
        tdiff = 0
        tdiff_norm = 0
    else:
        tdiff = max_th - th
        tdiff_norm = (tdiff/th)
    # print(str(tapp) + ": TDiffNorm = "+str(tdiff_norm))
    # print("Th = "+str(th)+ "MaxTh = "+str(max_th) + " TdiffNorm = "+str(tdiff_norm))
    output_data = str(tdiff_norm) + "\n"
    fp.write(output_data)
    if tdiff_norm > 1:
        tr_status = "Traffic differentiation detected"
    return tr_status


def mcl_process_app_data(nw, apps, app_data_list):
    b_th_info = mcl_calc_runavg_th(apps, app_data_list)
    # tapp = list(app_list.keys())[0]+"_1"
    for tapp in apps:
        # fname = "output_data/" + tapp + ".txt"
        fname = "./Report/" + nw + "/Results/" + tapp + ".txt"
        fp = open(fname, "a")
        # print("Test app = "+str(tapp))
        # print("log :"+str(fname))
        tr = mcl_detect_rep_nnvd(fp, apps, b_th_info, tapp)
        # print(tapp + " Result : "+tr)
        fp.close()


def mcl_generate_app_info(adata):
    import re
    app_info = []
    # print("adata = "+str(adata))
    adata = adata.split("\n")
    # print("adata = "+str(adata))
    for data in adata:
        if '' is data:
            continue
        if ":" not in data:
            continue
        if "Instance" in data or "ClientId" in data or "DEBUG" in data or "Download" in data or "Restarted" in data or "algo" in data or "Do" in data\
                or "THR" in data or "Traffic" in data or "Threshold" in data or "Partial" in data:
            continue
        # print(data)
        # print("P = "+str(data))
        p = data.split(":")
        ct = p[1]
        exp = int(ct.split("E")[1])
        mul = 10**exp
        ct = ct.replace("\'", "")
        ct = float(re.split(r"E\d+", ct)[0])
        ct = ct * mul
        ct = ct/1000
        cdlen = int(p[2])
        info = dinfo_struct(ct, cdlen)
        app_info.append(info)
    return app_info


def mcl_get_app_info_list(apps, app_data_list):
    app_info_list = {}
    app_oth_info = {}
    for app in apps:
        # print("App = "+str(app))
        apptype = str(app) + "_1"
        adata = app_data_list[app][0]
        # print("App = "+str(app))
        # print(app + ":" + adata)
        # print(app_data_list[app][2])
        # x = input()
        # x = input()
        app_info_list[apptype] = mcl_generate_app_info(adata)
        app_oth_info[apptype] = [app_data_list[app][1], app_data_list[app][2]]
        # print("Other info = "+str(app_oth_info[apptype]))
        # print(app_info_list[apptype])
    return app_info_list, app_oth_info


def mcl_get_app_list(apps):
    alist = {}
    i = 0
    for app in apps:
        alist[app] = {1}
    return alist


def mcl_get_td_cs(app, app_oth_info_list):
    td_cs = int(app_oth_info_list[app][0])
    if MAX_TD_CS < td_cs:
        td_cs = True
    else:
        td_cs = False
    return td_cs


def mcl_get_min_acdf_len(alist, acdf):
    lacdf = 0
    for app in alist:
        app = app + "_1"
        clacdf = len(acdf[app])
        if lacdf == 0:
            lacdf = clacdf
        if clacdf < lacdf:
            lacdf = clacdf
    return lacdf


def mcl_perform_ktest(alist, acdf):
    from scipy.stats import kstest, ks_2samp
    tks = 0
    i = 0
    xks = []
    lacdf = mcl_get_min_acdf_len(alist, acdf)
    for app in alist:
        app = app + "_1"
        adata = acdf[app][0:lacdf]
        capp = app
        for iapp in alist:
            iapp = iapp + "_1"
            if iapp != capp:
                iadata = acdf[iapp][0:lacdf]
                # Adjust the array size
                # print(str(len(adata)) + ":" + str(len(iadata)))
                # print(capp + ":" + iapp)
                x = ks_2samp(adata, iadata)
                i = 0
                for data in adata:
                    # print(str(data) + ":" + str(iadata[i]))
                    i += 1
                print(str(capp) + ":" + str(iapp) + " = " + str(x.pvalue))
                xks.append(x.pvalue)
                i += 1
    return xks


def mcl_adata_ktest_process_report(report):
    # from meas_client_analyse_packets import mcl_calc_per_app_data_cdf
    from meas_client_analyse_packets import mcl_get_app_test_label, mcl_calc_per_seg_app_data
    import matplotlib.pyplot as p
    p.cla()
    plot = True
    adata_cdf = {}
    print(report)
    # print("Processing report")
    # Get report data
    rdata = mcl_get_report_data(report)
    # print(rdata)
    # Get app list
    dsize, apps, app_data_list = mcl_get_app_data_list(rdata,1)
    # x = input()
    app_info_list, app_oth_info_list = mcl_get_app_info_list(apps, app_data_list)
    alist = mcl_get_app_list(apps)
    # Process report for each app
    for app in alist:
        app = app + "_1"
        adata = app_info_list[app]
        pindex, pth = mcl_calc_per_seg_app_data(None, adata)
        # pindex, pth = mcl_calc_per_app_data_cdf(None, adata)
        adata_cdf[app] = pth
        if plot:
            pcolor = app_to_color_map[app]
            applabel = mcl_get_app_test_label(app, 1)
            p.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
    if plot:
        p.xlabel('segment count', fontsize=12)
        p.ylabel('Server Per segment transmission speed (bps)', fontsize=15)
        p.grid(linestyle='--', linewidth=2)
        ax = p.subplot(111)
        ax.legend()
        ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
        p.tick_params(width=2, length=5, labelsize=13)
        p.savefig('output_data/seg_tx_speed.png')
        p.show()
    ktest = mcl_perform_ktest(alist, adata_cdf)
    return ktest


def mcl_chk_td_table(is_thr, is_cs, alen):
    td_status = "No-TD"
    if is_thr or is_cs and alen < MAX_DATA:
        td_status = "TD"
    return td_status


def mcl_get_td_status(td_info, alen):
    if td_info[0]:
        td_status = "Bad-Network"
    else:
        td_status = mcl_chk_td_table(td_info[1], td_info[2], alen)
    return td_status


def mcl_get_report_metadata(report):
    if "\\" in report:
        report = report.split("\\").pop().split("-")
    else:
        report = report.split("/").pop().split("-")
    return report


def mcl_get_user_data(report):
    from meas_client_global_const import num_installs, installs
    # print("Report = "+str(report))
    report = report[0] + report[1] + report[2] + report[3]
    # print("Report = "+str(report))
    # x = input()
    if report not in installs:
        # print("Adding user to database")
        installs.append(report)
    return report


def mcl_get_tdata(rmdata):
    #print("rmdata : "+str(rmdata))
    from datetime import datetime
    dt_info = {}
    t_info = {}
    #print(rmdata[5])
    ct = (rmdata).split("+")
    #print("ct : "+str(ct))
    ctime = ct[0]
    ctzone = ct[1]
    #print(ctime)
    clen = int(len(ctime)/2)
    #print(clen)
    cday = str(ctime[0:clen])
    ctime = str(ctime[clen:len(ctime)])
    #print(cday)
    #print(ctime)
    t_info[ctime] = {}
    dt_info[cday] = t_info
    #print(dt_info)
    return dt_info, t_info[ctime]


#def mcl_gen_user_db(report):
#    report_mdata = mcl_get_report_metadata(report)
#    user = mcl_get_user_data(report_mdata)
#    dt_info, t_info = mcl_get_tdata(report_mdata)
#    u_info[user] = dt_info
#    return t_info


def mcl_store_nl_data(nl_data, nl_ps_data):
    fname = "./input_data/nl_data.txt"
    fp = open(fname, "w")
    for nl in nl_data:
        fp.write(str(nl)+",")
    fp.close()
    fname = "./input_data/nl_ps_data.txt"
    fp = open(fname, "w")
    #for nl in nl_ps_data:
    #    fp.write(str(nl)+",")
    fp.write(str(nl_ps_data))
    fp.close()


def mcl_check_td_detect(td):
    for app in td:
        if td[app][0] == "TD":
            return True
    return False


def mcl_process_report(report, max_slot_time):
    from meas_client_analyse_packets import mcl_calc_time_windowed_athroughput, mcl_calc_iat, \
        mcl_calc_runavg_athroughput
    app_td_status = {}
    #print(report)
    #t_info = mcl_gen_user_db(report)
    #print(u_info)
    # print(t_info)
    # x = input()
    # print("Processing report")
    # Get report data
    rdata = mcl_get_report_data(report)
    if rdata == "":
        return None, None, None, None
    userid = report.split("-")
    userid_l = len(userid)
    # print("UserId : " + str(userid) + "  UserIDLen = " + str(userid_l))
    # print("UserId : " + str(userid[5]))
    # print(rdata)
    # Get app list
    dsize, apps, app_data_list = mcl_get_app_data_list(rdata, userid[userid_l-1])
    if apps is None or app_data_list is None or dsize < 20000000:
        return None, None, None, None
    #print("User name = " + str(meas_client_global_const.user_name))
    #print("User Info = " + str(meas_client_global_const.user_info))
    app_info_list, app_oth_info_list = mcl_get_app_info_list(apps, app_data_list)
    alist = mcl_get_app_list(apps)
    # Process report for each app
    # print(alist)
    td_status = False
    paap = 0
    bad_nw = False
    td_thr = False
    td_cs = False
    td = {}
    t_time = 0
    td_detect = False
    for app in alist:
        atype = app + "_1"
        adlen = int(app_oth_info_list[atype][1])
        if adlen != 0 and adlen < MAX_DATA:
            # print(adlen)
            paap += 1
    if paap == len(alist):
        bad_nw = True
    for app in alist:
        app = app + "_" + str(1)
        if bad_nw:
            td_thr = False
            td_cs = False
            t_time = 0
            tpth = None
        else:
            #print(alist)
            # mcl_calc_runavg_athroughput(alist, app_info_list)
            #mcl_calc_iat(None, alist, app_info_list)
            td_thr, t_time, tpth, nl_nt = mcl_calc_time_windowed_athroughput(app, alist, app_info_list, max_slot_time)
            td_cs = mcl_get_td_cs(app, app_oth_info_list)
        app_td_status[app] = [bad_nw, td_thr, td_cs]
        #if not td_status:
        adlen = int(app_oth_info_list[app][1])
        td_status = mcl_get_td_status(app_td_status[app], adlen)
        adlen = int(app_oth_info_list[app][1])
        ctd = mcl_get_td_status(app_td_status[app], adlen)
        td[app] = [ctd, bad_nw, td_thr, bool(td_cs), tpth, t_time, nl_nt]
        # print("App TD status = " + str(td))
        # mcl_process_app_data(nw, apps, app_data_list)
    mcl_store_nl_data(nl_count, nl_ps)
    # print("N_L Count : " + str(nl_count))
    # print("th_diff = " + str(th_diff_h2l))
    # mcl_plot_th_diff(th_diff_h2l)
    meas_client_global_const.user_result = td
    # print("User Result = " + str(meas_client_global_const.user_result))
    # x = input()
    # print("app_td_status = " + str(app_td_status) + "\n")
    # print("td_status = " + str(td_status) + "\n")
    td_detect = mcl_check_td_detect(td)
    return app_td_status, td_status, t_time, td_detect


def mcl_process_report_dy(report, max_slot_time, ththr, slthr, st):
    from meas_client_analyse_packets import mcl_calc_time_windowed_athroughput_dy, mcl_calc_iat, \
        mcl_calc_runavg_athroughput
    app_td_status = {}
    #print(report)
    #t_info = mcl_gen_user_db(report)
    #print(u_info)
    # print(t_info)
    # x = input()
    # print("Processing report")
    # Get report data
    rdata = mcl_get_report_data(report)
    if rdata == "":
        return None, None, None, None
    userid = report.split("-")
    userid_l = len(userid)
    # print("UserId : " + str(userid) + "  UserIDLen = " + str(userid_l))
    # print("UserId : " + str(userid[5]))
    # print(rdata)
    # Get app list
    dsize, apps, app_data_list = mcl_get_app_data_list(rdata, userid[userid_l-1])
    if apps is None or app_data_list is None or dsize < 20000000:
        return None, None, None, None
    #print("User name = " + str(meas_client_global_const.user_name))
    #print("User Info = " + str(meas_client_global_const.user_info))
    app_info_list, app_oth_info_list = mcl_get_app_info_list(apps, app_data_list)
    alist = mcl_get_app_list(apps)
    # Process report for each app
    # print(alist)
    td_status = False
    paap = 0
    bad_nw = False
    td_thr = False
    td_cs = False
    td = {}
    t_time = 0
    td_detect = False
    for app in alist:
        atype = app + "_1"
        adlen = int(app_oth_info_list[atype][1])
        if adlen != 0 and adlen < MAX_DATA:
            # print(adlen)
            paap += 1
    if paap == len(alist):
        bad_nw = True
    for app in alist:
        app = app + "_" + str(1)
        if bad_nw:
            td_thr = False
            td_cs = False
            t_time = 0
            tpth = None
        else:
            #print(alist)
            # mcl_calc_runavg_athroughput(alist, app_info_list)
            #mcl_calc_iat(None, alist, app_info_list)
            td_thr, t_time, tpth = mcl_calc_time_windowed_athroughput_dy(app, alist, app_info_list, max_slot_time, ththr, slthr, st)
            td_cs = mcl_get_td_cs(app, app_oth_info_list)
        app_td_status[app] = [bad_nw, td_thr, td_cs]
        #if not td_status:
        adlen = int(app_oth_info_list[app][1])
        td_status = mcl_get_td_status(app_td_status[app], adlen)
        adlen = int(app_oth_info_list[app][1])
        ctd = mcl_get_td_status(app_td_status[app], adlen)
        td[app] = [ctd, bad_nw, td_thr, bool(td_cs), tpth, t_time]
        # print("App TD status = " + str(td[app][0]) + " : " + str(adlen))
        # mcl_process_app_data(nw, apps, app_data_list)
    mcl_store_nl_data(nl_count, nl_ps)
    # print("N_L Count : " + str(nl_count))
    # print("th_diff = " + str(th_diff_h2l))
    # mcl_plot_th_diff(th_diff_h2l)
    meas_client_global_const.user_result = td
    # print("User Result = " + str(meas_client_global_const.user_result))
    # x = input()
    # print("app_td_status = " + str(app_td_status) + "\n")
    # print("td_status = " + str(td_status) + "\n")
    td_detect = mcl_check_td_detect(td)
    return app_td_status, td_status, t_time, td_detect


if __name__ == '__main__':
    mcl_process_report("./input_data/Reports/2-2ddf6f60-5716-415d-9d9a-c7f9169aba65-200122133600+0530", "")
