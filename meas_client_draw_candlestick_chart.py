# -*- coding: utf-8 -*-


def mcl_draw_cschart(index, open_data, high_data, low_data, close_data, xlabel, ylabel, fname):
    import matplotlib.pyplot as plt
    from mplfinance.original_flavor import candlestick_ohlc

    fig = plt.figure()
    ax = plt.subplot2grid((1, 1), (0, 0))

    l = len(open_data)
    ohlc = []
    for x in range(0, l):
        data = index[x], open_data[x], high_data[x], low_data[x], close_data[x]
        ohlc.append(data)

    candlestick_ohlc(ax, ohlc, width=4)
    plt.xlabel(xlabel, fontsize=15)
    plt.ylabel(ylabel, fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=15)
    plt.show()
    plt.savefig(fname)


def mcl_test_cschart():
    open_data = [33.0, 33.3, 33.5, 33.0, 34.1]
    high_data = [33.1, 33.3, 33.6, 33.2, 34.8]
    low_data = [32.7, 32.7, 32.8, 32.6, 32.8]
    close_data = [33.0, 32.9, 33.3, 33.1, 33.1]
    index = [0, 1, 2, 3, 4, 5]
    mcl_draw_cschart(index, open_data, high_data, low_data, close_data)


def mcl_draw_burst_size_cschart():
    open_data = [1198.014, 1186.175, 1573.24, 1675.167, 1535.393, 1647.208]
    low_data = open_data
    close_data = [1245.132, 1230.582, 1762.234, 1891.706, 1805.245, 1902.481]
    index = [12500, 25000, 50000, 100000, 150000, 200000]
    i = 0
    for data in close_data:
        # close_data[i] = (close_data[i] - open_data[i])
        index[i] = index[i]/1000
        # open_data[i] = 0
        i += 1
    high_data = close_data
    mcl_draw_cschart(index, open_data, high_data, low_data, close_data, 'Bursts size in Kb',
                     'Application Throughput(Kbps) span', 'bs_comp.png')


def mcl_draw_buff_size_cschart():
    open_data = [3431.13, 3428, 3307.685, 2570.62]
    low_data = open_data
    close_data = [3911.716, 3868.136, 3791.073, 2795.756]
    index = [20000, 50000, 70000, 100000]
    i = 0
    for data in close_data:
        # close_data[i] = (close_data[i] - open_data[i])
        index[i] = index[i]/1000
        # open_data[i] = 0
        i += 1
    high_data = close_data
    mcl_draw_cschart(index, open_data, high_data, low_data, close_data, 'TCP Send buffer size in Kb',
                     'Application Throughput(Kbps) span', 'buff_comp.png')


if __name__ == '__main__':
    # mcl_test_cschart()
    # mcl_draw_burst_size_cschart()
    # mcl_draw_buff_size_cschart()
    # mcl_draw_campaign_cschart()
