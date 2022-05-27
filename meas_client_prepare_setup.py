# -*- coding: utf-8 -*-

import os, sys
from meas_client_global_const import app_list

def mcl_copy_pcap_files(fpath):
    sfname = fpath + "\\pkts.pcap"
    if os.path.exists(sfname):
        for app in app_list:
            dfname = "input_data\\Pcap\\" + str(app) + "\\pkts.pcap"
            print(str(sfname) + " " + str(dfname))
            os.system("copy {0} {1}".format(sfname, dfname))
    else:
        print("Source pcap file does not exists")

def mcl_copy_pth_files(fpath):
    print("For pth "+str(fpath))
    for app in app_list:
        sfname = fpath + "\\pth_"+str(app)+".txt"
        dfname = "input_data\\Pth\\pth_" + str(app) + ".txt"
        if os.path.exists(dfname):
            #print("Deleting"+str(dfname))
            os.system("del /f {0} > 1".format(dfname))
        if os.path.exists(sfname):
            #print(str(sfname) + " " + str(dfname))
            os.system("copy {0} {1} > 1".format(sfname, dfname))
        else:
            print("Source path file does not exists")

def mcl_copy_files(comm,fpath):
    if "ANALYSE" == comm:
        mcl_copy_pcap_files(fpath)
    if "SHOW"== comm:
        mcl_copy_pth_files(fpath)

def mcl_prepare_setup():
    alen = len(sys.argv)
    if 2 > alen :
        fpath = 'output_data'
    else:
        fpath = sys.argv[1]
    mcl_copy_files(fpath)

if __name__ == '__main__':
    mcl_prepare_setup()