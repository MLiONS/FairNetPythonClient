# -*- coding : utf-8 -*-

from meas_client_utils import *


def mcl_get_per_app_per_isp_tds(mst, td):
    otd = {}
    for td_data in td:
        cmst = float(td_data[0])
        cmst = round (cmst, 3)
        # print(str(cmst) + ":" + str(mst))
        if cmst != mst:
            continue
        # print("MST = "+str(cmst))
        td_data_pm_l = td_data[1]
        # print("td_data_pm_l len = " + str(len(td_data_pm_l)))
        for td_data_pm in td_data_pm_l:
            td_data_pm_pa_l = td_data_pm[1]
            for td_data_pm_pa in td_data_pm_pa_l:
                # print("td_data_pm_pa : " + str(td_data_pm_pa) + "\n")
                if len(td_data_pm_pa) is 4:
                    capp = td_data_pm_pa[0]
                    if capp not in otd:
                        # New service added in td list
                        otd[capp] = [0, 0, 0]
                    td_dlen = int(td_data_pm_pa[1])
                    td_thr = int(td_data_pm_pa[2])
                    td_cs = int(td_data_pm_pa[3])
                    otd[capp][0] += td_dlen
                    otd[capp][1] += td_thr
                    otd[capp][2] += td_cs
                # else:
                    # print("td_data_pm_pa : File skipped")
    print(otd, end='')
    return otd


def mcl_get_per_app_td(td_data):
    td_thr = []
    td_range = []
    alabel = []
    if None == td_data:
        td_thr = [1, 1, 1, 1, 1, 1, 1, 1]
        td_range = [1, 1, 1, 1, 1, 1, 1, 1]
    else:
        for data in td_data:
            alabel.append(data)
            td_thr.append(td_data[data][0])
            td_range.append(td_data[data][1])
    return td_thr, td_range


def mcl_show_per_mst_per_isp_tds(td_data_isp1, td_data_isp2, dpath):
    import numpy as np
    import matplotlib.pyplot as p
    p.cla()
    alabel = []
    atd_isp1_thr, atd_isp1_range = mcl_get_per_app_td(td_data_isp1)
    atd_isp2_thr, atd_isp2_range = mcl_get_per_app_td(td_data_isp2)
    for data in td_data_isp1:
        alabel.append(data)
    num_app = len(alabel)
    X = np.arange(num_app)
    p.bar(X + 0.00, atd_isp1_thr, color='b', width=0.25)
    p.bar(X + 0.00, atd_isp1_range, color='g', width=0.25, bottom=atd_isp1_thr)
    p.bar(X + 0.25, atd_isp2_thr, color='b', width=0.25)
    p.bar(X + 0.25, atd_isp2_range, color='g', width=0.25, bottom=atd_isp2_thr)
    p.plot()
    p.grid(linestyle='--', linewidth=0.25)
    ax = p.subplot(111)
    ax.legend()
    fname = "isp_app_td_status_1_05.png"
    p.savefig(dpath+'/'+fname, dpi=600)
    p.show()
    p.cla()
    return


def mcl_process_per_app_per_isp_tds(td, dpath):
    mst = 0.75
    td_data = mcl_get_per_app_per_isp_tds(mst, td)
    # x = input()
    mcl_show_per_mst_per_isp_tds(td_data, None, dpath)
    return


def mcl_process_td_old(td):
    from matplotlib import pyplot as p
    import calendar
    import time
    import os
    p.cla()
    ts = calendar.timegm(time.gmtime())
    dpath = "Meas_results\\"+str(ts)
    os.system("mkdir {0}".format(dpath))
    fname = dpath + "\\report_data.txt"
    ofile = mcl_fopen(True, fname, "a", "CREATE")
    td_count_list = []
    td_thr_list = []
    td_range_list = []
    for td_info in td:
        max_slot_time = td_info[0]
        td_count_list.append(max_slot_time)
        td_thr = td_info[1][0]
        td_thr_list.append(td_thr)
        td_range = td_info[1][1]
        td_range_list.append(td_range)
        odata = str(max_slot_time) + ":" + str(td_thr) + ":" + str(td_range) + "\n"
        mcl_fwrite(True, ofile, odata)
    mcl_fwrite(True, ofile, "EOF")
    mcl_fclose(ofile)
    p.plot(td_count_list, td_thr_list, label='Threshold detection', color='green')
    p.plot(td_count_list, td_range_list, label='Range detection', color='blue')
    p.xlabel('slot size in sec.', fontsize=12)
    p.ylabel('Number of TD detected', fontsize=15)
    p.grid(linestyle='--', linewidth=2)
    ax = p.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    p.tick_params(width=2, length=5, labelsize=13)
    p.savefig(dpath+'/td_status.png')
    p.show()
    p.cla()


def mcl_show_per_mst_tds(td, dpath):
    from matplotlib import pyplot as p
    p.cla()
    td_count_list = []
    td_thr_list = []
    td_range_list = []
    for td_info in td:
        max_slot_time = round(float(td_info[0]), 2)
        td_count_list.append(max_slot_time)
        td_thr = td_info[1]
        td_thr_list.append(td_thr)
        td_range = td_info[2]
        td_range_list.append(td_range)
    p.plot(td_count_list, td_thr_list, label='Threshold detection', color='green')
    p.plot(td_count_list, td_range_list, label='Range detection', color='blue')
    p.xlabel('slot time in sec', fontsize=12)
    p.ylabel('Number of TDs detected', fontsize=15)
    p.grid(linestyle='--', linewidth=2)
    ax = p.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    p.tick_params(width=2, length=5, labelsize=13)
    p.savefig(dpath+'/td_status.png')
    p.show()
    p.cla()
    return


def mcl_get_per_mst_tds(td):
    otd = []
    td_dlen = 0
    td_thr = 0
    td_range = 0
    for td_data in td:
        mst = td_data[0]
        td_data_pm_l = td_data[1]
        for td_data_pm in td_data_pm_l:
            td_data_pm_pa_l = td_data_pm[1]
            for td_data_pm_pa in td_data_pm_pa_l:
                # td_data_pm_pa.split(",")
                # print(td_data_pm_pa[2])
                td_dlen += int(td_data_pm_pa[1])
                td_thr += int(td_data_pm_pa[2])
        # print(mst)
        otd_data = [mst, td_dlen, td_thr]
        otd.append(otd_data)
        td_thr = 0
        td_range = 0
    # print("OTD = " + str(otd))
    #   x = input()
    return otd


def mcl_process_per_mst_tds(td, dpath):
    td_data = mcl_get_per_mst_tds(td)
    mcl_show_per_mst_tds(td_data, dpath)
    return


def mcl_get_app_td(td_data):
    td_thr = []
    td_dlen = []
    td_cs = []
    alabel = []
    for data in td_data:
        td_dlen.append(td_data[data][0])
        td_thr.append(td_data[data][1])
        td_cs.append(td_data[data][2])
        alabel.append(data)
    return alabel, td_dlen, td_thr, td_cs


def mcl_show_per_app_tds(td_data, dpath):
    import numpy as np
    import matplotlib.pyplot as p
    bwidth = 0.25
    p.cla()
    print(td_data)
    alabel, atd_dlen, atd_thr, atd_cs = mcl_get_app_td(td_data)
    num_app = len(alabel)
    X = np.arange(num_app)
    x = range(num_app)
    p.bar(X + 0.00, atd_dlen, color='b', width=bwidth, label='Bad Network condition')
    p.bar(X + 0.00, atd_thr, color='g', width=bwidth, bottom=atd_dlen, label='Detected by Threshold Algo')
    p.bar(X + 0.00, atd_cs, color='r', width=bwidth, bottom=atd_dlen, label='Detected by Connection Status Algo')
    p.plot()
    p.grid(linestyle='--', linewidth=0.25)
    p.xlabel('Services', fontsize=15)
    p.ylabel('Count', fontsize=15)
    p.xticks(x, alabel)
    p.tick_params(width=2, length=5, labelsize=6)
    ax = p.subplot(111)
    ax.legend()
    fname = "app_td_status.png"
    p.savefig(dpath+'/'+fname, dpi=600)
    p.show()
    p.cla()
    return


def mcl_process_per_app_tds(td, dpath):
    mst = 1.875
    td_data = mcl_get_per_app_per_isp_tds(mst, td)
    mcl_show_per_app_tds(td_data, dpath)
    return


def mcl_process_td(td, dpath):
    # mcl_process_per_mst_tds(td, dpath)
    # mcl_process_per_app_per_isp_tds(td, dpath)
    mcl_process_per_app_tds(td, dpath)


def mcl_get_results(dpath):
    import os
    ostype = os.name
    # Get results from Meas_results/ to input_data/Reports/
    if "nt" == ostype:
        sfname = dpath+str("\\report_data.txt")
        dfname = "input_data\\Report_data\\report_data.txt"
        os.system("copy {0} {1}".format(sfname, dfname))
    else:
        sfname = dpath.replace("\\", "/") + str("/report_data.txt")
        dfname = "input_data/Report_data/report_data.txt"
        print(sfname)
        os.system("cp {0} {1}".format(sfname, dfname))
    return


def mcl_move_logfile(td, rdir, fname):
    import os
    ostype = os.name
    my_mv = "move"
    if "nt" == ostype:
        dpath = rdir.replace("/", "\\") + str(td)
        # spath = rdir.replace("/", "\\") + fname
        spath = fname.replace("/", "\\")
    else:
        dpath = rdir + str(td)
        spath = fname
        my_mv = "mv"
    if not os.path.exists(dpath):
        # print("Inside = " + dpath)
        os.system("mkdir {0}".format(dpath))
    #print("dpath = " + dpath)
    #print("spath = " + spath)
    if str(td) not in spath:
        os.system("{0} {1} {2}".format(my_mv, spath, dpath))


def mcl_handle_report(com):
    from meas_client_process_report import mcl_process_report
    import calendar
    import time
    import os
    ts = calendar.timegm(time.gmtime())
    i = 0
    max_slot_time = 1.875
    rcount = 0
    if "RUN" == com or "ALL" == com:
        # print("Creating new dir ")
        ostype = os.name
        if "nt" == ostype:
            dpath = "Meas_results\\"+str(ts)
            os.system("mkdir {0}".format(dpath))
            ofname = dpath + "\\report_data.txt"
        else:
            dpath = "Meas_results/"+str(ts)
            os.system("mkdir {0}".format(dpath))
            ofname = dpath + "/report_data.txt"
        ofile = mcl_fopen(True, ofname, "w", None)
        odata = "max slot size = " + str(max_slot_time) + "\n"
        ofile.write(odata)
        mcl_fclose(ofile)
    rdir = "./input_data/Reports/"
    fnames = mcl_get_logfile_list(com, rdir)
    # print("File names : " + str(fnames))
    if len(fnames) == 0:
        print("No report to analyse....Exiting")
        sys.exit()
    else:
        for fname in fnames:
            rcount += 1
            # print(fname)
            fname = fname.replace("\\", "/")
            #print(fname)
            # rfname = rdir + fname
            print("Log no. " + str(rcount) + " : " + fname)
            if os.path.isdir(fname):
                continue
            app_td_status, td, t_time, td_detect = mcl_process_report(fname, max_slot_time)
            if app_td_status is None or td is None:
                print("No analysis done\n")
                continue
            # print("TD status = "+str(td))
            # mcl_move_logfile(td, rdir, fname)
            if "RUN" == com or "ALL" == com:
                ofile = mcl_fopen(True, ofname, "a", None)
                odata = "File:"+str(fname)+str(";")
                ofile.write(odata)
                odata = ""
                td_dlen = False
                for app in app_td_status:
                    # print(app)
                    capp = app.split("_")[0]
                    odata += str(capp) + ":"
                    # if app not in td_status:
                    # print(app + ": " + str(td_status))
                    #    td_status[app] = [0, 0]
                    td_dlen = app_td_status[app][0]
                    td_thr = app_td_status[app][1]
                    td_cs = app_td_status[app][2]
                    odata += str(int(td_dlen))
                    odata += ","
                    odata += str(int(td_thr))
                    odata += ","
                    odata += str(int(td_cs))
                    odata += "|"
                i += 1
                odata += "\n"
                ofile.write(odata)
                mcl_fclose(ofile)
    if "RUN" == com or "ALL" == com:
        ofile = mcl_fopen(True, ofname, "a", None)
        odata = "EOF"
        ofile.write(odata)
        mcl_fclose(ofile)
        # print("2:" + dpath)
        mcl_get_results(dpath)
        mcl_show_result(dpath)


def mcl_get_pa_td_data(idata):
    td = []
    # print("idata = "+str(idata))
    idata = idata.split(":")
    if len(idata) > 1:
        app = idata[0]
        td_info = idata[1].split(",")
        td_dlen = td_info[0]
        td_thr = td_info[1]
        td_cs = td_info[2]
        td = [app, td_dlen, td_thr, td_cs]
    # else:
        # print("mcl_get_pa_td_data : File skipped")
    return td


def mcl_get_pf_td_data(idata):
    td = []
    idata = idata.split("|")
    lidata = len(idata)
    # print("lidata = " + str(lidata) + " : " + str(idata))
    if len(idata) > 0:
        if len(idata) > 1:
            for data in idata:
                if "" != data:
                    td_data_pa = mcl_get_pa_td_data(data)
                    td.append(td_data_pa)
        else:
            td_data_pa = mcl_get_pa_td_data(idata[0])
            td.append(td_data_pa)
    # else:
        # print("mcl_get_pf_td_data : file skipped")
    return td


def mcl_get_per_file_results(idata):
    td = []
    td_data = []
    idata = idata.split(";")
    lidata = len(idata)
    # print("lidata = " + str(lidata) + " : " + str(idata))
    fname = idata[0].split(":")[1]
    if len(idata) == 2:
        td_data = mcl_get_pf_td_data(idata[1])
    # else:
        # print("File skipped")
    # print(td_data)
    td = [fname, td_data]
    return td


def mcl_get_td(ifile):
    td = []
    rdata = ifile.readline()
    mst = None
    td_data_pf = None
    td_data_pm = None
    rcount = 0;
    while "EOF" != rdata:
        rdata = rdata.strip("\n")
        rdatas = rdata.split(";")
        if len(rdatas) == 2:
            if rdata.split(";")[1] is not "":
                rcount += 1
                print(str(rcount) + " :: " + str(rdata.split(";")[1]))
        # else:
            # print(str(rcount) + " : " + str(""))
        # print(rdata)
        if "slot" in rdata:
            if None != td_data_pm:
                td.append([mst, td_data_pm])
            td_data_pm = []
            mst = rdata.split("=")[1]
            # print("mst = " + str(mst))
            rdata = ifile.readline()
            continue
        if "File" in rdata:
            td_data_pf = mcl_get_per_file_results(rdata)
            # print(td_data_pf)
        td_data_pm.append(td_data_pf)
        # print("td_data_pm = " + str(td_data_pm))
        rdata = ifile.readline()
        if "EOF" == rdata:
            td.append([mst, td_data_pm])
    # print(td)
    # x = input()
    # print("td_data_pm len = " + str(len(td_data_pm)))
    return td


def mcl_show_result(dpath):
    import calendar
    import time
    import os
    ostype = os.name
    ts = calendar.timegm(time.gmtime())
    print("Showing results")
    if None is dpath:
        if "nt" == ostype:
            dpath = "Meas_results\\"+str(ts)
        else:
            dpath = "Meas_results/"+str(ts)
        os.system("mkdir {0}".format(dpath))
    fname = "input_data/Report_data/report_data.txt"
    ifile = mcl_fopen(True, fname, "r", None)
    td = mcl_get_td(ifile)
    # print("\ntd = " + str(td) + "\n")
    mcl_process_td(td, dpath)
    if "nt" == ostype:
        sfname = "input_data\\Report_data\\report_data.txt"
        dfname = dpath+str("\\report_data.txt")
        os.system("copy {0} {1}".format(sfname, dfname))
    else:
        sfname = "input_data/Report_data/report_data.txt"
        dfname = dpath+str("/report_data.txt")
        os.system("cp {0} {1}".format(sfname, dfname))


if __name__ == "__main__":
    import sys
    alen = len(sys.argv)
    if 1 == alen:
        print("Please provide command line options : RUN/SHOW ")
        sys.exit()
    else:
        com = sys.argv[1]
    if "RUN" == com or "CLASSIFY" == com or "ALL" == com:
        mcl_handle_report(com)
    elif "SHOW" == com:
        mcl_show_result(None)
    elif "CLASSIFY" == com:
        mcl_handle_report(com)
    else:
        print("Wrong argument"+"\n"+"Please provide command line options : RUN/SHOW ")
    sys.exit()
