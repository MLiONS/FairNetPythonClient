# -*- coding : utf-8 -*-

import meas_client_utils
from meas_client_global_const import *

def meas_client_display_from_pth_file(app):
    data = []
    dindex = []
    fname = "input_data/Pth/pth_"+str(app)+".txt"
    fp = open(fname,"r")
    line = fp.readline()
    while line != '':
        #print(line)
        linecomp = line.split(' ')
        complen = len(linecomp)
        #print(str(complen))
        if complen < 7:
            line = fp.readline()
            continue
        a = float(line.split(' ')[0].split('\n')[0])
        b = float(line.split(' ')[6].split('\n')[0])
        data.append(b)
        dindex.append(a)
        #print(str(a)+' '+str(b))
        line = fp.readline()
    return dindex, data
