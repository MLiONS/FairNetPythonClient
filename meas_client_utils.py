# -*- coding: utf-8 -*-
def mcl_delete_file(fname):
    import os
    if os.path.exists(fname):
        os.remove(fname)


def mcl_fopen(DEBUG,fname,com,info):
    import os
    if DEBUG:
        if "DELETE" == info and os.path.exists(fname):
            os.remove(fname)
        return open(fname,com)


def mcl_fclose(file_p):
    if file_p:file_p.close()


def mcl_fwrite(DEBUG,fp,output_data):
    if DEBUG:
        if fp: fp.write(output_data)


def mcl_copy_file(sfname, dfname):
    import platform
    import os
    stype = platform.platform()
    if "mac" in stype:
        os.system("cp -rf {0} {1}".format(sfname, dfname))


def mcl_move_file(sfname, dfname):
    import platform
    import os
    stype = platform.platform()
    if "mac" in stype:
        os.system("mv {0} {1}".format(sfname, dfname))
    # Add more OS specific command


def mcl_make_dir(dname):
    import platform
    import os
    stype = platform.platform()
    if "mac" in stype:
        os.system("mkdir {0}".format(dname))


def mcl_delete_file(fname):
    import platform
    import os
    stype = platform.platform()
    if "mac" in stype:
        os.system("\\rm -rf {0}".format(fname))


def mcl_get_ssl_socket(sock, rserver):
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Original TLSv1
    context.load_cert_chain('../SSL_cert/server.cert', '../SSL_cert/server.key')
    s = context.wrap_socket(sock, server_hostname=rserver)
    return s


def mcl_get_logfile_list(com, rdir):
    import os
    import glob
    print(rdir)
    if "CLASSIFY" == com:
        # fnames = os.listdir(rdir)
        sdir = rdir + "/*"
        fnames = glob.glob(sdir, recursive=True)
    else:
        sdir = rdir + "/**/*"
        fnames = glob.glob(sdir, recursive=True)
    #for file in fnames:
    #    print(file)
    #x = input()
    return fnames


def mcl_plot_data(l_data, xlabel, ylabel, pfile):
    import matplotlib.pyplot as p
    p.cla()
    i = 0
    thindex = []
    for data in l_data:
        thindex.append(i)
        i += 1
    p.plot(thindex, l_data, markersize=20, linewidth=2)
    p.xlabel(xlabel, fontsize=12)
    p.ylabel(ylabel, fontsize=15)
    p.grid(linestyle='--', linewidth=2)
    # ax = p.subplot(111)
    # ax.legend()
    # ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    p.tick_params(width=2, length=5, labelsize=13)
    p.savefig(pfile)
    p.show()


def mcl_draw_bar_chart(l_data, xlabel, ylabel, pfile):
    import numpy as np
    import matplotlib.pyplot as p
    p.cla()
    alabel = []
    for i in range (0, 6):
        alabel.append(l_data[i])
    print(alabel)
    num_app = len(alabel)
    X = np.arange(num_app)
    p.xlabel("Throughput in Mbps", fontsize=12)
    p.ylabel("Occurrences", fontsize=12)
    p.bar(X+0.5, alabel, color='b', width=1)
    p.plot()
    p.grid(linestyle='--', linewidth=0.25)
    ax = p.subplot(111)
    ax.legend()
    p.savefig(pfile, dpi=600)
    p.show()
    p.cla()
