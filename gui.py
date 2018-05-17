from Tkinter import *
from tkMessageBox import *
from main import ip_chk,start,p2p_detected,bot_detected
import socket,ipaddress,threading
import fcntl
import struct
import array

ip_status = {}


def is_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match:
		return False
	quad = []
	for number in match.groups():
		quad.append(int(number))
	if quad[0] < 1:
		return False
	for number in quad:
		if number > 255 or number < 0:
			return False
	return True


def all_interfaces():
    max_possible = 128  # arbitrary. raise if needed.
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()

    lst = []
    for i in range(0, outbytes, 40):
        name = namestr[i:i+16].split('\0', 1)[0]
        #ip   = namestr[i+20:i+24]
        lst.append(name)
    return lst



def submit():	
	global frame2
	global ip_status
	if opt.get() == 1:
		
		ips = txtar.get("1.0",'end-1c')
		if ips.strip() == "":			
			showwarning('Warning', 'No ip mentioned')
		else:
			ips = ips.split(",")		
			i=0
			for ip in ips:
				if not is_ipv4(ip):
					showwarning('Warning', 'Not valid ip '+ip)
					return
				var = StringVar()
				var.set("NOT P2P")				
				ip_chk.append(str(ip))				
				lbl = Label(frame2.interior,text = str(ip),font=("Arial", 12))
				lbl.grid(row=i+1,column=0,padx=(0,40),sticky=W)
				#frame2.lbips.append(lbl)
				lbl = Label(frame2.interior, textvariable = var ,fg = "green",font=("Arial", 12))
				lbl.grid(row=i+1,column=1,sticky=W)				
				#frame2.lbstatus.append(lbl)
				ip_status[str(ip)] = (var,lbl)
				i+=1
				
			frame2.tkraise()
			#thr = threading.Thread(target=start,kwargs={'iface': iface.get()})
			thr = threading.Thread(target=start)
			thr.daemon = True
			thr.start()			
	elif opt.get()== 2:
		net = netw.get()
		try:
			net = ipaddress.IPv4Network(unicode(net))
			i=1
			for ip in net:
				var = StringVar()
				var.set("NOT P2P")				
				ip_chk.append(str(ip))				
				lbl = Label(frame2.interior,text = str(ip),font=("Arial", 12))
				lbl.grid(row=i+1,column=0,padx=(0,40),sticky=W)
				#frame2.lbips.append(lbl)
				lbl = Label(frame2.interior, textvariable = var ,fg = "green",font=("Arial", 12))
				lbl.grid(row=i+1,column=1,sticky=W)				
				#frame2.lbstatus.append(lbl)
				ip_status[str(ip)] = (var,lbl)
				i+=1
			
			frame2.tkraise()
			#thr = threading.Thread(target=start,kwargs={'iface': iface.get()})
			thr = threading.Thread(target=start)
			thr.daemon = True
			thr.start()
		except ValueError as e:
			showwarning('Warning', str(e))


class FrameTwo(Frame):    
	
    def __init__(self, parent,ip_status):
        Frame.__init__(self, parent)
	#self.configure(width = 200)
        # create a canvas object and a vertical scrollbar for scrolling it
        vscrollbar = Scrollbar(self, orient=VERTICAL, width = 20)
        vscrollbar.pack(fill=Y, side=RIGHT)
        canvas = Canvas(self, bd=0, highlightthickness=0,yscrollcommand=vscrollbar.set,height=400)
        canvas.pack(side=LEFT, fill=BOTH)
        vscrollbar.config(command=canvas.yview)

        # reset the view
        canvas.xview_moveto(0)
        canvas.yview_moveto(0)

        # create a frame inside the canvas which will be scrolled with it
        self.interior = interior = Frame(canvas,height=400)
        interior_id = canvas.create_window(0, 0, window=interior,anchor=NW)

        # track changes to the canvas and frame width and sync them,
        # also updating the scrollbar

        def _configure_interior(event):
            # update the scrollbars to match the size of the inner frame
            size = (interior.winfo_reqwidth(), interior.winfo_reqheight())
            canvas.config(scrollregion="0 0 %s %s" % size)
            if interior.winfo_reqwidth() != canvas.winfo_width():
                # update the canvas's width to fit the inner frame
                canvas.config(width=interior.winfo_reqwidth())
        interior.bind('<Configure>', _configure_interior)

        def _configure_canvas(event):
            if interior.winfo_reqwidth() != canvas.winfo_width():
                # update the inner frame's width to fill the canvas
                canvas.itemconfigure(interior_id, width=canvas.winfo_width())
        canvas.bind('<Configure>', _configure_canvas)

	Label(interior,text = "IP",font=("Arial", 13,"bold")).grid(row=0,column=0,padx=(0,40),sticky=W)	
	Label(interior,text = "STATUS",font=("Arial", 13,"bold")).grid(row=0,column=1,sticky=W)	

	#self.lbips= []
	#self.lbstatus = []
	#self.ip_status = ip_status	




def Refresher(): 
    #print(len(frame2.lbips),len(frame2.lbstatus))
    for x in ip_status:	
	if x in bot_detected:
		ip_status[x][0].set("BOT DETECTED")
		ip_status[x][1].config(fg="red")
	elif x in p2p_detected:
		ip_status[x][0].set("P2P DETECTED")
		ip_status[x][1].config(fg="yellow")
	
    root.after(1000, Refresher)


root = Tk()
root.geometry('%dx%d+%d+%d' % (640, 500, 200, 100))

opt = IntVar()
iface = StringVar()
netw = StringVar()
root.title("P2P botnet detection")
Label(root, text="P2P Botnet Detection",font=("Arial", 16,"bold")).grid(row=0,column=0,pady=10,sticky=W)
frame1 = Frame(root)
frame1.grid(row=1,column=0,sticky="nsew")

frame2 = FrameTwo(root,ip_status)
frame2.grid(row=1,column=0,sticky="nsew")



r1 = Radiobutton(frame1, text="Enter IPs list comma seperated",font=("Arial", 12), variable=opt, value=1)
r1.select()
r1.grid(row=0,column=0,sticky=W)

txtar = Text(frame1, height=4,width=90)
txtar.grid(row=2,column=0,sticky=W)

Radiobutton(frame1, text="Enter Network(CIDR notation)",font=("Arial", 12), variable=opt, value=2).grid(row=3,column=0,pady=(30,0),sticky=W)
Entry(frame1, width = 60, font=("Arial", 12), textvariable=netw).grid(row=4,column=0,sticky=W)
Label(frame1, text="Select interface for detection",font=("Arial", 12,"bold")).grid(row=5,column=0,pady=(30,5),sticky=W)

interfaces = all_interfaces()
fr = Frame(frame1)
fr.grid(row=6,column=0,sticky=W)
for x in range(len(interfaces)):
	if x == 0:
		rb = Radiobutton(fr, text=interfaces[x], variable=iface,font=("Arial", 12), value=interfaces[x])
		rb.select()
		rb.pack(side=LEFT)
	else:	
		Radiobutton(fr, text=interfaces[x], variable=iface,font=("Arial", 12), value=x).pack(side=LEFT)

Button(frame1, text ="Start Detection", command = submit , bg="#999999",fg="white").grid(row=7,column=0,pady=10,sticky=W)
frame1.tkraise()

Refresher()
mainloop()
        

