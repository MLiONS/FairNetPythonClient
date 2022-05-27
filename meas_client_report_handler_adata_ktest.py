# -*- coding : utf-8 -*-
from meas_client_utils import *


def mcl_get_ktest_stat(ks_res):
    tres = 0
    lres = len(ks_res)
    for res in ks_res:
        if res > 0.9:
            tres += res
    ks_stat = (tres*100)/lres
    # Remove Netflix issue traces
    print("KS Test stat = "+str(ks_stat))


def mcl_adata_ktest_handle_report():
    from meas_client_process_report import mcl_adata_ktest_process_report
    import calendar
    import time
    import os
    ts = calendar.timegm(time.gmtime())
    i = 0
    ks_res = []
    ostype = os.name
    if "nt" == ostype:
        dpath = "Meas_results\\" + str(ts)
        os.system("mkdir {0}".format(dpath))
        ofname = dpath + "\\report_data.txt"
    else:
        dpath = "Meas_results/" + str(ts)
        os.system("mkdir {0}".format(dpath))
        ofname = dpath + "/report_data.txt"
    rdir = "./input_data/Reports/No-TD"
    fnames = mcl_get_logfile_list(com, rdir)
    if len(fnames) == 0:
        print("No report to analyse....Exiting")
    else:
        for fname in fnames:
            fname = fname.replace("\\", "/")
            if os.path.isdir(fname):
                continue
            ofile = mcl_fopen(True, ofname, "a", None)
            odata = "File:"+str(fname)+str(";")
            ofile.write(odata)
            mcl_fclose(ofile)
            # rfname = rdir + fname
            # print(rfname)
            ktest = mcl_adata_ktest_process_report(fname)
            # print(ktest)
            if type(ktest) == float:
                ks_res.append(ktest)
            else:
                for res in ktest:
                    ks_res.append(res)
            # x = input()
            ofile = mcl_fopen(True, ofname, "a", None)
            odata = str(ktest)
            odata += "\n"
            ofile.write(odata)
            mcl_fclose(ofile)
    mcl_get_ktest_stat(ks_res)
    ofile = mcl_fopen(True, ofname, "a", None)
    odata = "EOF"
    ofile.write(odata)
    mcl_fclose(ofile)
    # mcl_get_results(dpath)
    # mcl_show_result(dpath)


if __name__ == "__main__":
    import sys
    alen = len(sys.argv)
    if 1 == alen:
        print("Please provide command line options : RUN/SHOW ")
        sys.exit()
    else:
        com = sys.argv[1]
    if "RUN" == com:
        mcl_adata_ktest_handle_report()
    elif "SHOW" == com:
        mcl_adata_ktest_show_result(None)
    else:
        print("Wrong argument"+"\n"+"Please provide command line options : RUN/SHOW ")
    sys.exit()
