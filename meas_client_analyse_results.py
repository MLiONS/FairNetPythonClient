
ISP_LIST = ['Hathway', "Vodafone", 'Airtel', "jio", "Home", 'VI', 'Bsnl', 'Hireach', 'Alliance',
            'Optaqon', 'ACT', 'Alliance']

APP_LIST = ["NTEFLIX_1", "PRIMEVIDEO_1", "HOTSTAR_1", "YOUTUBE_1", "MXPLAYER_1", "HUNGAMA_1"
            "VOOT"]

import matplotlib.pyplot as plt

def mcl_get_gen_stats(res):
    import json
    usrs = []
    locs = []
    isps = []
    ispl = {}
    tcs = 0
    fname = "./output_data/summary.txt"
    fp = open(fname, "w")
    for user in res:
        if user not in usrs:
            usrs.append(user)
        for loc in res[user][0]:
            if "NA" in loc or "Permission denied" in loc or "success" in loc\
                    or "status" in loc or "HTTP" in loc or "None" in loc:
                continue
            if loc not in locs:
                locs.append(loc)
            for isp in res[user][0][loc]:
                if "192." in isp or "127." in isp or "Local" in isp or "null" in isp or \
                        "WiFi name" in isp or "None" in isp or "{" in isp or "LOCAL" in isp \
                        or "NA" in isp:
                    continue
                if isp not in isps:
                    isps.append(isp)
                if isp not in ispl:
                    ispl[isp] = 0
                else:
                    ispl[isp] += 1
        tcs += 1
    print("Total logs = " + str(tcs))
    output_data = str(tcs) + "\n"
    fp.write(str(output_data))
    print("Total users = "+str(len(usrs)))
    output_data = str(usrs) + "\n"
    fp.write(str(output_data))
    print("Total countries = "+str(len(locs)))
    output_data = str(locs) + "\n"
    fp.write(str(output_data))
    print("Countries = "+str(locs))
    output_data = str(locs) + "\n"
    fp.write(str(output_data))
    print("Total ISPs = "+str(len(isps)))
    output_data = str(isps) + "\n"
    fp.write(str(output_data))
    print("ISPs = "+str(isps))
    output_data = str(isps) + "\n"
    fp.write(str(output_data))
    print("Logs per ISP : " + str(ispl))
    output_data = str(ispl) + "\n"
    fp.write(str(output_data))
    fp.close()
    return tcs


def mcl_get_raw_res():
    import ast
    fname = "input_data/td_raw_res.txt"
    with open(fname) as fp:
        data = fp.read()
    # print("Data type before reconstruction : ", type(data))
    res = ast.literal_eval(data)
    # print(res)
    # print("Data type after reconstruction : ", type(res))
    return res


def mcl_loc_filter(loc):
    filt = False
    if "NA" in loc or "Permission denied" in loc or "success" in loc \
            or "status" in loc or "HTTP" in loc or "None" in loc:
        filt = True
    return filt


def mcl_isp_filt(isp):
    filt = False
    if "192." in isp or "127." in isp or "Local" in isp or "null" in isp or \
            "WiFi name" in isp or "None" in isp or "{" in isp or "LOCAL" in isp \
            or "NA" in isp:
        filt = True
    return filt


def mcl_get_td_app_in_isp (isp_info):
    tdapp = []
    for day in isp_info:
        for ctime in isp_info[day]:
            for app in isp_info[day][ctime]:
                tds = isp_info[day][ctime][app][0]
                if tds == "TD":
                    t_time = isp_info[day][ctime][app][5]
                    tdapp.append([app, t_time])
    return tdapp


def mcl_gen_comb_td_results(res) -> object:
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
        for loc in res[user][0]:
            # if "NA" in loc or "Permission denied" in loc or "success" in loc\
            #        or "status" in loc or "HTTP" in loc or "None" in loc:
            if mcl_loc_filter(loc):
                continue
            for isp in res[user][0][loc]:
                # if "192." in isp or "127." in isp or "Local" in isp or "null" in isp or \
                #        "WiFi name" in isp or "None" in isp or "{" in isp or "LOCAL" in isp \
                #        or "NA" in isp:
                if mcl_isp_filt(isp):
                    continue
                if isp not in iatd:
                    iatd[isp] = {}
                    itd[isp] = [0, 0, 0]
                for day in res[user][0][loc][isp]:
                    for ctime in res[user][0][loc][isp][day]:
                        for app in res[user][0][loc][isp][day][ctime]:
                            if app not in atd:
                                atd[app] = [0, 0, 0]
                            if app not in iatd[isp]:
                                iatd[isp][app] = [0, 0, 0]
                            if app not in aitd:
                                aitd[app] = {}
                            if isp not in aitd[app]:
                                aitd[app][isp] = [0, 0, 0]
                            tds = res[user][0][loc][isp][day][ctime][app][0]
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
    #print(output_data)
    fp.write(output_data)
    output_data = "ISP-Application TD status : " + str(iatd) + "\n"
    #print(output_data)
    fp.write(output_data)
    output_data = "Application-ISP TD status : " + str(aitd) + "\n"
    #print(output_data)
    fp.write(output_data)
    output_data = "ISP TD status : " + str(itd) + "\n"
    #print(output_data)
    fp.write(output_data)
    fp.close()
    return td, atd, iatd, aitd, itd


def mcl_get_isp_app_td_info(isp_td, isp, appl):
    # print("Generating APP TDs for " + str(isp))
    i = 1
    y = []
    x = []
    num_td = 0
    for isp_td_info in isp_td:
        num_td += isp_td_info
    if num_td == 0:
        return
    for isp_td_info in isp_td:
        x.append(i)
        y.append(isp_td_info)
        i += 1
    print(x)
    print(y)
    xlabel = "Apps"
    ylabel = "Number of TDs"
    fname = "./output_data/" + str(isp.replace(" ", "")) + "_isp_app_td.png"
    mcl_draw_cplot(x, y, xlabel, ylabel, appl, fname, None, [5, 5], None, 0.15, 30,
                   'right')


def mcl_generate_td_summary(iatd):
    #import pandas as pd
    appl = []
    ispl = []
    numtdl = []
    isp_td = []
    isp_td_df = {}
    #appl.append("ISPs")
    for isp in iatd:
        for app in iatd[isp]:
            app_name = app.split("_")[0]
            if app_name not in appl:
                appl.append(app_name)
    for isp in iatd:
        num_td = []
        num_td_d = {}
        if isp not in ispl:
            ispl.append(str(isp))
        for app in appl:
            num_td_d[app] = 0
        for app in iatd[isp]:
            app_name = app.split("_")[0]
            if app_name not in appl:
                appl.append(app_name)
            num_td_d[app_name] = iatd[isp][app][0]
        #num_td.append(isp)
        for app in num_td_d:
            num_td.append(num_td_d[app])
        isp_td.append(num_td)
        isp_td_df[isp] = num_td
        #print(str(isp) + " : " + str(num_td))
        #print(str(num_td))
    #print("ISP App TD : " + str(isp_td_df))
    fname = "./output_data/isp_app_td.txt"
    fp = open(fname, "a")
    fp.write(str(appl))
    fp.write(str(isp_td_df))
    fp.close()
    for isp in isp_td_df:
        mcl_get_isp_app_td_info(isp_td_df[isp], isp, appl)
    return appl


def mcl_get_isp_td_info(td, isps):
    i = 1
    y = []
    x = []
    isp_tds = {}
    isp_names = []
    for isp in isps:
        isp_tds[isp] = 0
    for td_info in td:
        isp = td_info[2]
        for tds in td_info[3]:
            if isp in isp_tds:
                isp_tds[isp] += 1
            else:
                isp_tds[isp] = 1
    isp_names = []
    x.append(0)
    y.append(0)
    isp_names.append("")
    for isp in isp_tds:
        ispname = mcl_get_isp_name(isp)
        if isp_tds[isp] <= 0:
            continue
        isp_names.append(ispname)
        x.append(i)
        y.append(isp_tds[isp])
        i += 1
    print(x)
    print(y)
    print("ISPss = " + str(isp_names))
    xlabel = "ISPs"
    ylabel = "Number of TDs"
    fname = "./output_data/isp_td.png"
    mcl_draw_cplot(x, y, xlabel, ylabel, isp_names, fname, None, [5, 5], None,0.15, 30,
                   'right')


def mcl_analyse_td_duration(res):
    t_duration = 0
    num_res = 0
    td_info = []
    cont = False
    tdapp = None
    for user in res:
        for loc in res[user][0]:
            if cont:
                break
            # if "NA" in loc or "Permission denied" in loc or "success" in loc\
            #        or "status" in loc or "HTTP" in loc or "None" in loc:
            if mcl_loc_filter(loc):
                cont = True
                break
            for isp in res[user][0][loc]:
                if mcl_isp_filt(isp):
                # if "192." in isp or "127." in isp or "Local" in isp or "null" in isp or \
                #        "WiFi name" in isp or "None" in isp or "{" in isp or "LOCAL" in isp \
                #        or "NA" in isp:
                    cont = True
                    break
        if cont:
            cont = False
            continue
        duration = res[user][1]
        if duration >= 180:
            continue
        td = res[user][2]
        t_duration += duration
        num_res += 1
        if td:
            cisp = None
            for loc in res[user][0]:
                for isp in res[user][0][loc]:
                    cisp = isp
                    tdapp = mcl_get_td_app_in_isp(res[user][0][loc][isp])
            td_res = [duration, user, cisp, tdapp]
            td_info.append(td_res)
            output_data = str(duration) + ":" + str(user) + ":" + str(cisp) + ":" + str(tdapp)
            print(output_data)
    print("TD Info : " + str(td_info))
    avg_duration = t_duration/num_res
    output_data = "Average min log duration : " + str(avg_duration)
    print(output_data)
    return td_info, avg_duration


def mcl_draw_cplot(x, y, xlabel, ylabel, xtlabel, fname, dline, fsize, dcolor, spsize,
                   rot, cha):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    fig = plt.figure(figsize=(fsize[0], fsize[1]))
    fig.tight_layout()
    fig.subplots_adjust(bottom=spsize)
    barlist=plt.bar(xtlabel, y, width=0.20)
    if dcolor is not None:
        for idx in dcolor:
            barlist[idx].set_color('r')
    if dline is not None:
        x_coordinates = [dline[0], dline[2]]
        y_coordinates = [dline[1], dline[3]]
        plt.plot(x_coordinates, y_coordinates, color='r')
    plt.xlabel(xlabel, fontsize=16)
    plt.ylabel(ylabel, fontsize=16)
    plt.xticks(x, rotation=rot, ha=cha)
    plt.grid(linestyle='--', linewidth=1)
    plt.tick_params(width=2, length=5, labelsize=7)
    plt.savefig(fname)
    #plt.show()


def mcl_get_isp_name(isp):
    print("ISP : " + str(isp))
    ispname = None
    if "hathway" in isp or "Hathway" in isp:
        ispname = "Hathway"
    elif "Airtel" in isp or "airtel" in isp:
        ispname = "Airtel"
    elif "Vodafone" in isp or "vodafone" in isp:
        ispname = "Vodafone"
    elif "Amogh" in isp:
        ispname = "Amogh"
    elif "Reliance" in isp:
        ispname = "Jio"
    elif "Home" in isp:
        ispname = "Home"
    else:
        ispname = isp
    print("ISP name : " + str(ispname))
    return ispname


def mcl_get_isp_info(res):
    isp_count = {}
    isp_name = "None"
    isp_names = []
    for user in res:
        for loc in res[user][0]:
            if mcl_loc_filter(loc):
                continue
            for isp in res[user][0][loc]:
                if mcl_isp_filt(isp):
                    continue
                for iname in ISP_LIST:
                    isp_name = isp
                    if isp in iname:
                        isp_name = iname
                        break
                isp_name = mcl_get_isp_name(isp)
                # print("ISP Info : " + isp_count)
                if isp_name in isp_count:
                    isp_count[isp_name] += 1
                else:
                    isp_count[isp_name] = 1
    output_data = "ISP Log count :" + str(isp_count)
    print(output_data)
    i = 1
    y = []
    x = []
    isps = []
    for isp in isp_count:
        if isp_count[isp] < 8:
            continue
        isp_name = mcl_get_isp_name(isp)
        print("ISP name p : " + str(isp_name))
        x.append(isp_name)
        isps.append(isp_name)
        y.append(isp_count[isp])
        i += 1
        isp_names.append(isp_name)
    print(x)
    print(y)
    xlabel = "ISPs"
    ylabel = "Number of logs"
    fname = "./output_data/isp_info.png"
    mcl_draw_cplot(x, y, xlabel, ylabel, isps, fname, None, [5, 5], None, 0.15, 30,
                   'right')
    return isp_names


def mcl_get_possible_tds(td_info, avgd):
    cong_td = 0
    td = 0
    i = 0
    y = []
    x = []
    td_idx = []
    print("Possible deliberate TDs")
    for td_res in td_info:
        for tds in td_res[3]:
            x.append(int(i+1))
            #y.append(td_res[0])
            # print(tds[1])
            y.append(tds[1])
            if td_res[0] < avgd:
                td_idx.append(i)
                assert isinstance(td_res, object)
                print(td_res)
            i += 1
    print(x)
    print(y)
    xlabel = "Detected NN violations"
    ylabel = "Minimum download duration"
    fname = "./output_data/td_test_duration.png"
    mcl_draw_cplot(x, y, xlabel, ylabel, x, fname, [0, avgd, i, avgd], [5, 5], td_idx,
                   0.1, 0, 'center')


def mcl_plot_th(isp, app, x, y):
    import matplotlib.pyplot as plt
    import numpy as np
    applabel = app.split("_")[0]
    pcolor = 'blue'
    plt.plot(x, y, label=applabel, markersize=20, linewidth=2, color=pcolor)
    # print(x)
    # print(y)
    PLT_ON = 1
    if PLT_ON == 1:
        plt.xlabel('Seconds', fontsize=12)
        plt.ylabel('Cumulative Application Throughput(bps)', fontsize=15)
        plt.grid(linestyle='--', linewidth=2)
        ax = plt.subplot(111)
        # ax.legend()
        ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
        plt.tick_params(width=2, length=5, labelsize=13)
        fname = "output_data/" + str(isp.replace(" ", "")) + "_twraath.png"
        plt.savefig(fname)
        # plt.show()


def mcl_draw_isp_app_th(app, isp_app_th):
    import matplotlib.pyplot as plt
    for isp in isp_app_th:
        plt.cla()
        app_th = isp_app_th[isp]
        print("ISP : " + str(isp) + " : " + str(len(app_th)))
        if len(app_th) < 10:
            continue
        # print(app_th)
        for th in app_th:
            ltime = th[len(th)-1]
            if ltime > 6000000:
                continue
            i = 0
            x = []
            y = []
            for th_info in th:
                x.append(i)
                y.append(float(th_info))
                i += 1
            applabel = app.split("_")[0]
            pcolor = 'blue'
            plt.plot(x, y, label=applabel, markersize=20, linewidth=2, color=pcolor)
        PLT_ON = 1
        if PLT_ON == 1:
            plt.xlabel('Seconds', fontsize=12)
            plt.ylabel('Cumulative Application Throughput(bps)', fontsize=15)
            plt.grid(linestyle='--', linewidth=2)
            ax = plt.subplot(111)
            # ax.legend()
            ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
            plt.tick_params(width=2, length=5, labelsize=13)
            fname = "output_data/" + str(isp.replace(" ", "")) + "_" + str(app.replace("_1","")) + "_twraath.png"
            plt.savefig(fname)
            # plt.show()


def mcl_get_isp_app_th_info(appl, res):
    i = 0.0
    x = []
    for app in appl:
        appname = str(app) + "_1"
        tapp = appname
        print("App : " + str(tapp))
        isp_app_th = {}
        for user in res:
            for loc in res[user][0]:
                if mcl_loc_filter(loc):
                    continue
                for isp in res[user][0][loc]:
                    if mcl_isp_filt(isp):
                        continue
                    for day in res[user][0][loc][isp]:
                        for ctime in res[user][0][loc][isp][day]:
                            for app in res[user][0][loc][isp][day][ctime]:
                                if app != tapp:
                                    continue
                                # print(str(isp) + " : " + str(app))
                                pth = res[user][0][loc][isp][day][ctime][app][4]
                                if pth is None:
                                    continue
                                y = []
                                for th in pth:
                                    x.append(i)
                                    y.append(float(th))
                                    i += 1.0
                                if isp in isp_app_th:
                                    isp_app_th[isp].append(y)
                                else:
                                    isp_app_th[isp] = []
                                    isp_app_th[isp].append(y)
                    # print(isp_app_th)
                    # z = input()
        # print(isp_app_th)
        mcl_draw_isp_app_th(tapp, isp_app_th)


def mcl_get_num_td_info(ntd, th, sl, p, ax):
    import math
    print("Number of TDs detected = " + str(ntd))
    pi = math.pi
    r = math.sqrt(ntd/pi)
    print("Radius = "+str(r))
    Drawing_colored_circle = p.Circle((th,sl), r)
    ax.add_artist(Drawing_colored_circle)
    print("TD info generated")
    return p, ax


def mcl_get_nl_analysis(ththr, slthr):
    import matplotlib.pyplot as plt_nl
    from meas_client_global_const import nl_count
    lindex = []
    lnl = []
    i = 0
    for nl in nl_count:
        lindex.append(i)
        i+=1
    plt_nl.plot(lindex, nl_count, markersize=20, linewidth=2)
    plt_nl.xlabel('logs', fontsize=15)
    plt_nl.ylabel('Number of low throughput slots', fontsize=15)
    plt_nl.grid(linestyle='--', linewidth=2)
    ax = plt_nl.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt_nl.tick_params(width=2, length=5, labelsize=13)
    plt_nl.savefig("output_data/" + str(ththr) + "_" + str(slthr) + "_nl.png")
    # plt_nl.show()


def mcl_analyse_results(res):
    print("Analysing report results")
    if None is res:
        res = mcl_get_raw_res()
    mcl_get_gen_stats(res)

    # Print ISP Info
    isp_names = mcl_get_isp_info(res)

    # Get n_l time range analysis
    # nl_cdf_idx, nl_cdf = mcl_get_nl_analysis()
    # print("NL CDF Count : " + str(nl_cdf_idx))
    # print("NL CDF = " + str(nl_cdf))

    # Get per slot n_l analysis
    # mcl_get_nl_perslot_analysis()

    # Get TD analysis
    ntd, atd, iatd, aitd, itd = mcl_gen_comb_td_results(res)
    #appl = mcl_generate_td_summary(iatd)

    # Get TD and duration analysis per ISP
    td_info, avgd = mcl_analyse_td_duration(res)

    # Get per ISP TD analysis
    mcl_get_isp_td_info(td_info, isp_names)

    # Get Possible TDs
    mcl_get_possible_tds(td_info, avgd)

    # Get per-isp-per-app throughput plots
    # mcl_get_isp_app_th_info(appl, res)

    # Get number of TDs per combination of slot threshold and throughput threshold
    #mcl_get_num_td_info(ntd, 1, 0.2)


if __name__ == '__main__':
    mcl_analyse_results(None)
