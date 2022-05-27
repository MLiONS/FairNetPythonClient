import os
app = "HOTSTAR"
sfname = "D:\\Vinod\\Code\\Meas_client\\output_data\\pkts.pcap"
dfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\"+str(app)+"\\pkts.pcap"
print("Copying "+str(sfname)+" to "+str(dfname))
os.system("copy {0} {1}".format(sfname, dfname))
