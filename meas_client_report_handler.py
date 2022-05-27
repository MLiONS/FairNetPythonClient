# -*- coding : utf-8 -*-


def mcl_handle_report():
    import os
    from meas_client_process_report import mcl_process_report
    store = True
    td_status = {}
    i = 0
    rdir = "./input_data/Reports/"
    fnames = os.listdir(rdir)
    max_slot_time = 0.8
    if len(fnames) == 0:
        print("No report to analyse....Exiting")
        store = False
    else:
        for fname in fnames:
            rfname = rdir + fname
            # print(rfname)
            app_td_status, td, t_time, td_detect  = mcl_process_report(rfname, max_slot_time)
            # print("APP TD STATUS = "+str(app_td_status))
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
            i+=1
            # x = input()
    print("Total TCs = "+str(i))
    return store


if __name__ == "__main__":
    mcl_handle_report()