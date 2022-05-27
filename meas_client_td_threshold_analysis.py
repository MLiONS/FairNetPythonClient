from meas_client_main import mcl_process_report_bunch_dy, mcl_store_results
from meas_client_analyse_results import mcl_get_num_td_info, mcl_get_raw_res, mcl_get_gen_stats, mcl_gen_comb_td_results, mcl_get_nl_analysis
from meas_client_utils import mcl_copy_file
 
def mcl_copy_raw_res():
    sfname = "output_data/td_raw_res.txt"
    dfname = "input_data/td_raw_res.txt"
    mcl_copy_file(sfname, dfname)
    print(str(sfname) + "moved to " + str(dfname))


def mcl_td_thr_main(gen_res):
    import matplotlib.pyplot as plt
    #ththrl = [0.250, 0.5, 0.750, 1]
    #slthrl = [0.2, 0.3, 0.4, 0.5]
    #fname = "output_data/"+"thsl_num_td.png"
    ththrl = [1]
    slthrl = [0.2]
    #figure, axes = plt.subplots()
    for ththr in ththrl:
        for slthr in slthrl:
            figure, axes = plt.subplots()
            print("Thresholds : " + str(ththr) + " , " + str(1-slthr))
            if "Y" == gen_res:
              store = mcl_process_report_bunch_dy("TEST", ththr*1000000, slthr)
              mcl_copy_raw_res()
            res = mcl_get_raw_res()
            num_logs = mcl_get_gen_stats(res)
            ntd, atd, iatd, aitd, itd = mcl_gen_comb_td_results(res)
            print("Number of TDs : " + str(ntd))
            p, ax = mcl_get_num_td_info(ntd/num_logs, ththr, slthr, plt, axes)
            plt = p
            axes = ax
            axes.set(xlim=(0, 1.5), ylim=(0, 1))
            #axes.set_aspect(1)
            #axes.add_artist(Drawing_colored_circle)
            plt.grid(linestyle='--', linewidth=2)
            plt.xlabel('Throughput threshold', fontsize=12)
            plt.ylabel('Slot threshold', fontsize=12)
            title = "throughput threshold = " + str(ththr) + " slot threshold = " + str(slthr) 
            plt.title(title)
            fname = "output_data/"+str(ththr)+"_"+str(slthr)+"_num_td.png"
            plt.savefig(fname)
            plt.cla()
            mcl_get_nl_analysis(ththr, slthr)
            if store == True:
              mcl_store_results("TEST")
    #plt.title('Colored Circle')
    #plt.savefig(fname)
    #plt.show()

if __name__ == '__main__':
    gen_res = "Y"#input("Generate results? (Y/N): ")
    mcl_td_thr_main(gen_res)
