
from collections import namedtuple
app_info = namedtuple("app_info", ["app", "param1", "param2"])

def mcl_process_single_report():
    from meas_client_process_report import mcl_process_report
    td_status = {}
    rname = input("Please enter name of report: ")
    if not rname:
        # rname = "80f7feb9-9f2a-40ff-9015-79638a3aad28-191222231555+0530"
        rname = "d998fbd1-67cb-4203-8117-84fe1ae0d430-200719043839+0530"
    report = "./input_data/Reports/"+rname
    # mcl_process_report("Report/e796a606-0f0c-4942-b66d-fa118acfd051-200104032019+0530")
    app_td_status, td, t_time, td_detect = mcl_process_report(report, "")
    print(app_td_status)
    for app in app_td_status:
        if app not in td_status:
            td_status[app] = [0, 0]
        td_thr = app_td_status[app][0]
        td_range = app_td_status[app][1]
        if td_thr:
            td_status[app][0] += 1
        if td_range:
            td_status[app][1] += 1
    print(td_status)
    x = input()


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
        if not rdir:
            # rdir = "./Report/" + nw + "/Logs/"
            rdir = "./input_data/Reports/"
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
                for app in app_td_status:
                    if app not in td_status:
                        td_status[app] = [0, 0]
                    td_thr = app_td_status[app][0]
                    td_range = app_td_status[app][1]
                    if td_thr:
                        td_status[app][0] += 1
                    if td_range:
                        td_status[app][1] += 1
                #print(td_status)
                mcl_update_results()
                #print("User Info post : " + str(u_info))
                i+=1
                #x = input()
    fname = "output_data/td_raw_res.txt"
    fp = open(fname, "a")
    fp.write(str(meas_client_global_const.u_info))
    fp.close()
    return store


def fairnet_meas_report_analyzer_main(nw, conn, fpath):
    mode = input("Number of reports (SINGLE/BUNCH)")
    if "SINGLE" == mode:
        mcl_process_single_report()
    else:
        mcl_process_report_bunch(nw)


if __name__ == '__main__':
    import sys
    nw = input("ISP (e.g. AIRTEL)")
    comm = input("SNIFF/DD/DOWNLOAD/ANALYSE/REPORT/ANALYZE_REPORT/SHOW/ALL:")
    alen = len(sys.argv)
    if 2 > alen:
        fpath = 'output_data'
    else:
        fpath = sys.argv[1]
    fairnet_meas_report_analyzer_main(nw, comm, fpath)
