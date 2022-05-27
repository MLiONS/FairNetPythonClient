from meas_client_main import mcl_process_report_bunch_dy, mcl_store_results
from meas_client_analyse_results import mcl_get_num_td_info, mcl_get_raw_res, mcl_get_gen_stats, \
    mcl_gen_comb_td_results, mcl_get_nl_analysis
from meas_client_utils import mcl_copy_file
import meas_client_global_const


TD_APPS = ["YOUTUBE_1", "PRIMEVIDEO_1", "HOTSTAR_1", "NETFLIX_1", "WYNK_1", "GAANA.COM_1"]
nl = 0
num_ip_tds = 0
num_ip_ntds = 0
num_cl_tds = 0
num_cl_ntds = 0
td_cla_error = 0;

def mcl_copy_raw_res():
    sfname = "output_data/td_raw_res.txt"
    dfname = "input_data/td_raw_res.txt"
    mcl_copy_file(sfname, dfname)
    print(str(sfname) + "moved to " + str(dfname))


def mcl_generate_classification_info(td, rfname):
    global nl
    global num_ip_tds
    global num_ip_ntds
    global num_cl_tds
    global num_cl_ntds
    global td_cla_error
    app1_td = None
    app2_td = None
    acount = 0
    ciptd = False
    ccltd = False
    appl = []
    for app in td:
        appl.append(app)
        nl += 1
        ctd = td[app][0]
        if "TD" == ctd:
            num_cl_tds += 1
            ccltd = True
        else:
            num_cl_ntds += 1
        if app in TD_APPS:
            if acount == 0:
                app1_td = True
                # print("App1 TD")
            else:
                app2_td = True
                # print("App2 TD")
        acount += 1
    if app1_td and app2_td or not app1_td and not app2_td:
        num_ip_ntds += 2
    else:
       num_ip_tds += 1
       num_ip_ntds += 1
       ciptd = True
    # print(str(appl))
    # print(str(nl) + " : " + str(num_ip_tds) + " : " + str(num_ip_ntds) + "\n")


def mcl_gen_cl_summary(ththr, slthr, st):
    global td_cla_error
    fname = "./output_data/" + str(ththr) + "_" + str(slthr) + "_" + str(st) + ".txt"
    fp = open(fname, "a")
    output_data = "Th Thr = " + str(ththr) + " : " + "Slot thr = " + str(slthr) + " : " + "Slot time" + str(st) + '\n'
    output_data += "Total number of samples : " + str(nl) + "\n"
    #print("Total number of samples : " + str(nl))
    output_data += "Total number of ip TDs : " + str(num_ip_tds) + "\n"
    #print("Total number of ip TDs : " + str(num_ip_tds))
    output_data += "Total number of ip NTDs : " + str(num_ip_ntds) + "\n"
    #print("Total number of ip NTDs : " + str(num_ip_ntds))
    output_data += "Total number of cl TDs : " + str(num_cl_tds) + "\n"
    #print("Total number of cl TDs : " + str(num_cl_tds))
    output_data += "Total number of cl NTDs : " + str(num_cl_ntds) + "\n"
    #print("Total number of cl NTDs : " + str(num_cl_ntds))
    td_cla_error = ((num_ip_tds - num_cl_tds)/(2*num_ip_tds))*100
    # td_cla_error = ((num_ip_tds - num_cl_tds)/num_cl_tds)*100
    output_data += "TD classification error : " + str(td_cla_error) + "\n"
    #print("TD classification error : " + str(td_cla_error))
    ntd_cla_error = ((num_ip_ntds - num_cl_ntds)/num_cl_ntds)*100
    output_data += "NTD classification error : " + str(ntd_cla_error) + "\n"
    #print("TD classification error : " + str(ntd_cla_error))
    print(output_data)
    fp.write(output_data)
    fp.close()


def mcl_process_report_bunch_cl(nw, rdir, ththr, slthr, st):
    import os
    from meas_client_process_report import mcl_process_report_dy
    store = True
    td_status = {}
    th_data = []
    i = 0
    gen_res = True
    fcount = 0
    if gen_res:
        fnames = os.listdir(rdir)
        lfcount = len(fnames)
        if len(fnames) == 0:
            print("No report to analyse....Exiting")
            store = False
        else:
            rcount = 0
            for fname in fnames:
                if "." in fname:
                    continue
                rfname = rdir + fname
                # print(rfname)
                app_td_status, td_status, t_time, td_detect = mcl_process_report_dy(rfname, "", ththr, slthr, st)
                td = meas_client_global_const.user_result
                mcl_generate_classification_info(td, rfname)
                fcount += 1
                print("Completed : " + str(fcount*100/lfcount) + "%", end="\r")
        mcl_gen_cl_summary(ththr, slthr, st)
    return store


def mcl_draw_td_info(r, th, sl, st, p, ax, lcolor):
    import math
    clabel = "Slot time = " +  str(st)
    pi = math.pi
    r = math.sqrt(math.fabs(r/100))
    print("Radius : " + str(r))
    Drawing_colored_circle = p.Circle((th,sl), r, color=lcolor, label=clabel)
    ax.add_artist(Drawing_colored_circle)
    return p, ax


def mcl_td_classerr_main(gen_res):
    import matplotlib.pyplot as plt
    global nl
    global num_ip_tds
    global num_ip_ntds
    global num_cl_tds
    global num_cl_ntds
    #ththrl = [1.75]
    #slthrl = [0.3]
    #stl = [1, 2]
    #cst = {1:"red", 2.5:"blue"}
    ththrl = [0.750, 1, 1.5, 1.75]
    slthrl = [0.2, 0.3, 0.4, 0.5]
    stl = [1, 1.5, 1.750, 2]
    cst = {1:"red", 1.5: "black", 1.750: "green", 2:"blue"}
    rdir = "./input_data/TDReports/"
    print("rdir : " + str(rdir))
    for slthr in slthrl:
        for ththr in ththrl:
            figure, axes = plt.subplots()
            for st in stl:
                #fname = "./output_data/" + str(ththr) + "_" + str(slthr) + "_" + str(st) + ".txt"
                #fp = open(fname, "w")
                print("Slot time = " + str(st) + "    Thresholds : " + str(ththr) + " , " + str(1 - slthr))
                #output_data = "Slot time = " + str(st) + "    Thresholds : " + str(ththr) + " , " + str(1 - slthr) + "\n"
                #fp.write(output_data)
                #fp.close()
                # print("log file : " + str(fname))
                if "Y" == gen_res:
                    store = mcl_process_report_bunch_cl("TEST", rdir, ththr * 1000000, slthr, st)
                p, ax = mcl_draw_td_info(td_cla_error, ththr, slthr, st, plt, axes, cst[st])
                plt = p
                axes = ax
                nl = 0
                num_ip_tds = 0
                num_ip_ntds = 0
                num_cl_tds = 0
                num_cl_ntds = 0
            axes.set(xlim=(0, 2), ylim=(0, 1))
            # axes.set_aspect(1)
            # axes.add_artist(Drawing_colored_circle)
            plt.grid(linestyle='--', linewidth=2)
            plt.xlabel('Throughput threshold', fontsize=12)
            plt.ylabel('Slot threshold', fontsize=12)
            title = "throughput threshold = " + str(ththr) + " slot threshold = " + str(slthr)
            plt.title(title)
            fname = "output_data/" + str(ththr) + "_" + str(slthr) + "_st_num_td.png"
            plt.savefig(fname)
            plt.cla()
    if "Y" == gen_res:
        mcl_store_results("TEST")

if __name__ == '__main__':
    gen_res = "Y"  # input("Generate results? (Y/N): ")
    mcl_td_classerr_main(gen_res)
