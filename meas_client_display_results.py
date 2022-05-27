# -*- coding : utf-8 -*-

from scapy.all import *
from meas_client_utils import mcl_fopen, mcl_fclose, mcl_fwrite
from meas_client_global_const import *
from meas_client_file_process import meas_client_display_from_pth_file
from meas_client_prepare_setup import mcl_copy_files

import warnings
warnings.filterwarnings("ignore")

def mcl_display_runavg_throughput():
    for app in app_list:
        pindex, pth = meas_client_display_from_pth_file(app)
        pcolor = app_to_color_map[app]
        fp = open("output_data/pi.txt","w")
        for i in range (1,len(pindex)):
            #pindex[i]=pindex[i]/1000
            output_data = str(i)+" "+str(pindex[i])+" "+str(pth[i])+'\n'
            fp.write(output_data)
        fp.close()
        plt.plot(pindex, pth, label=app, markersize=20, linewidth=5, color=pcolor)
    plt.xlabel('Number of packets', fontsize=12)
    plt.ylabel('Cumulative Throughput(kbps)', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.set_xlim(0, MAX_NUM_PKTS)
    ax.ticklabel_format(style='sci', scilimits=(-2,3),useLocale=True)
    plt.tick_params(width=5, length=5, labelsize=13)
    plt.savefig('output_data/rath.png')

def mcl_display_results_main(comm,fpath):
    mcl_copy_files(comm,fpath)
    mcl_display_runavg_throughput()
    #mcl_calc_inst_throughput(app_pkt_info)
    #mcl_calc_time_window_avg_throughput(app_pkt_info)
    #mcl_calc_sliding_time_window_avg_throughput(app_pkt_info)
    #mcl_calc_throughput_var(app_pkt_info)

