from tkinter import *
from meas_client_main import mcl_main

window = Tk()
window.title("MonStrS")
window.geometry('650x600')
global btn

def start_meas_client():
    import time
    import threading
    isp = sui.get()
    comm = pui.get()
    fpath = "output_data"
    fpath = fui.get()
    pth = threading.Thread(target=mcl_main, args=(isp, comm, fpath))
    pth.start()
    print("Thread completed")
    btn.configure(state=NORMAL)
    #btn.destroy()
    #sbtn = Button(window, text="START", command=start_meas_client)
    #sbtn.grid(column=0, row=3)
    #btn = sbtn

def exit_meas_client():
    btn.destroy()
    window.destroy()

slbl = Label(window, text="ISP (e.g. AIRTEL):")
slbl.grid(column=0, row=0)
sui = Entry(window,width=14)
sui.grid(column=1, row=0)

plbl = Label(window, text="Command (DOWNLOAD/ANALYSE/SHOW/ALL):")
plbl.grid(column=0, row=1)
pui = Entry(window,width=14)
pui.grid(column=1, row=1)

slbl = Label(window, text="Stored logs:")
slbl.grid(column=0, row=2)
fui = Entry(window,width=14)
fui.grid(column=1, row=2)

sbtn = Button(window, text="START", command=start_meas_client)
sbtn.grid(column=0, row=3)
btn = sbtn

ebtn = Button(window, text="EXIT", command=exit_meas_client, justify=RIGHT)
ebtn.grid(column=1, row=3)

#print("Displaying result")
#photo = PhotoImage(file=r'D:\Vinod\Code\Meas_client\input_data\rath.gif')
#lphoto = Label(window, image=photo)
#lphoto.grid(column=0, row=300, columnspan=2)

window.mainloop()
