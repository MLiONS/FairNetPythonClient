
def mcl_draw_cplot(x, y, xlabel, ylabel, xtlabel):
    import matplotlib.pyplot as plt
    for xe, ye in zip(x, y):
        plt.scatter([xe] * len(ye), ye)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(x)
    plt.axes().set_xticklabels(xtlabel)
    plt.grid(linestyle='--', linewidth=1)
    plt.tick_params(width=2, length=5, labelsize=7)
    plt.savefig('campaign.png')
    plt.show()


def  mcl_get_campaign_apps(fnames):
    apps = []
    for fname in fnames:
        app = fname.split(".")[0]
        apps.append(app)
    return apps


def mcl_get_tr_values(fname):
    rdir = "./Report/Vodafone/Results/"
    r = []
    fname = rdir + fname
    fp = open(fname, "r")
    l = fp.readline().rstrip("\n")
    l = float(l)
    while l != "":
        l = float(l)
        if l < 10:
            r.append(l)
        l = fp.readline().strip("\n")
    # print(r)
    res = tuple(r)
    # print(res)
    return res


def mcl_draw_campaign_plot():
    import os
    y = []
    x = []
    rdir = "./Report/Vodafone/Results/"

    fnames = os.listdir(rdir)

    apps = mcl_get_campaign_apps(fnames)
    # print(apps)

    i = 1
    for app in apps:
        x.append(i)
        i += 1
    # print(x)

    for fname in fnames:
        tr = mcl_get_tr_values(fname)
        y.append(tr)
    # print(y)

    xlabel = "Services"
    ylabel = "Normalised traffic differentiation"
    mcl_draw_cplot(x, y, xlabel, ylabel, apps)


def mcl_test_cplot():
    y = [(1, 1, 2, 3, 9), (1, 1, 2, 4)]
    x = [1, 2]
    xtlabel = ['cat1', 'cat2']
    mcl_draw_cplot(x, y, xtlabel)


if __name__ == '__main__':
    # mcl_test_cplot()
    mcl_draw_campaign_plot()
