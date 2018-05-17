import pyshark,re
import sys, time, os
from numpy import median
            
class FlowData:
    def __init__(self):
        self.meanintertime = 0 
        self.fwdbytes = 0 #only data
        self.bkdbytes = 0
        self.fdp=0
        self.bdp=0
        self.totdata=0 #including headers
        self.pktsmall=0
        self.pktlarge=0
        self.mxintertime=float(-sys.maxint-1)
        self.mnintertime=float(sys.maxint)
        self.totalduration=0
        self.meanpkttime = 0 #duration/no pkt check
        self.meanfwdinter = 0
        self.meanbkdinter = 0
        self.mxfwdintertime = float(-sys.maxint-1)
        self.mxbkdintertime = float(-sys.maxint-1)
        self.mnfwdintertime = float(sys.maxint)
        self.mnbkdintertime = float(sys.maxint)
        #self.proto = 0 #udp or tcp
        self.ffwd_ts = None
        self.fbkd_ts = None
        self.las_ts = None
        self.lasfwd_ts = None
        self.lasbkd_ts = None
        self.f_ts = None
            
        
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

def HandlePacket(pkt):
    global ip_chk
    s_ip = pkt.ip.src
    d_ip = pkt.ip.dst
    if s_ip not in ip_chk and d_ip not in ip_chk:
        return
    prot_str=re.findall(r"([a-zA-Z0-9]*)\sLayer", str(pkt.layers))
    flag = 0
    
    if "TCP" in prot_str:
        flag = 1        
        flw = (s_ip,pkt.tcp.srcport,d_ip,pkt.tcp.dstport)
        flw2 = (d_ip,pkt.tcp.dstport,s_ip,pkt.tcp.srcport)
                
    elif "UDP" in prot_str:
        flag = 1        
        flw = (s_ip,pkt.udp.srcport,d_ip,pkt.udp.dstport)
        flw2 = (d_ip,pkt.udp.dstport,s_ip,pkt.udp.srcport)
   
    if flag == 1 and flw in flow_dat.keys():               
            dat=flow_dat[flw]      
            dat.fdp+=1
            dat.totdata+=int(pkt.length)
            if "TCP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("TCP")].len)
            elif "UDP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("UDP")].length)
            dat.pktsmall = min(int(pkt.length),dat.pktsmall)
            dat.pktlarge = max(int(pkt.length),dat.pktlarge)
            dat.mxintertime = max(dat.mxintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.mnintertime = min(dat.mnintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.mxfwdintertime = max(dat.mxfwdintertime,float(pkt.sniff_timestamp)-dat.lasfwd_ts)
            dat.mnfwdintertime = min(dat.mnfwdintertime,float(pkt.sniff_timestamp)-dat.lasfwd_ts)            
            dat.totalduration = float(pkt.sniff_timestamp)-dat.f_ts
            dat.las_ts = dat.lasfwd_ts = float(pkt.sniff_timestamp)
                                    
            
    elif flag == 1 and flw2 in flow_dat.keys():            
            dat=flow_dat[flw2]
            dat.bdp+=1
            dat.totdata+=int(pkt.length)
            if "TCP" in prot_str:
                dat.bkdbytes += int(pkt.layers[prot_str.index("TCP")].len)
            elif "UDP" in prot_str:
                dat.bkdbytes += int(pkt.layers[prot_str.index("UDP")].length)
            dat.pktsmall = min(int(pkt.length),dat.pktsmall)
            dat.pktlarge = max(int(pkt.length),dat.pktlarge)
            dat.mxintertime = max(dat.mxintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.mnintertime = min(dat.mnintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.totalduration = float(pkt.sniff_timestamp)-dat.f_ts
            if dat.fbkd_ts is None:
                dat.las_ts = dat.lasbkd_ts = dat.fbkd_ts = float(pkt.sniff_timestamp)
            else:
                dat.mxbkdintertime = max(dat.mxbkdintertime,float(pkt.sniff_timestamp)-dat.lasbkd_ts)
                dat.mnbkdintertime = min(dat.mnbkdintertime,float(pkt.sniff_timestamp)-dat.lasbkd_ts)
                dat.las_ts = dat.lasbkd_ts = float(pkt.sniff_timestamp)            
            
    elif flag == 1:           
            dat=flow_dat[flw]=FlowData()            
            dat.fdp+=1
            if "TCP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("TCP")].len)
            elif "UDP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("UDP")].length)
            dat.pktsmall = dat.pktlarge = dat.totdata = int(pkt.length)
            dat.f_ts = dat.las_ts = dat.lasfwd_ts = dat.ffwd_ts = float(pkt.sniff_timestamp)            
            

def extractFeatures(key):
    dat = flow_dat[key]
    if dat.mxintertime == float(-sys.maxint-1):
        dat.mxintertime=0
    if dat.mnintertime == float(sys.maxint):
        dat.mnintertime = 0
    if dat.mxfwdintertime == float(-sys.maxint-1):
        dat.mxfwdintertime = 0
    if dat.mxbkdintertime == float(-sys.maxint-1):
        dat.mxbkdintertime = 0 
    if dat.mnfwdintertime == float(sys.maxint):
        dat.mnfwdintertime = 0
    if dat.mnbkdintertime == float(sys.maxint):
        dat.mnbkdintertime = 0
    if dat.fdp+dat.bdp-1 != 0:
        dat.meanintertime = (dat.las_ts - dat.f_ts)/(dat.fdp+dat.bdp-1)
    else:
        dat.meanintertime = 0
    dat.meanpkttime = dat.totalduration/(dat.fdp+dat.bdp)
    if dat.fdp-1 !=0:
        dat.meanfwdinter = (dat.lasfwd_ts-dat.ffwd_ts)/(dat.fdp-1)
    else:
        dat.meanfwdinter = 0
    if dat.fbkd_ts == None or dat.bdp-1 == 0:
        dat.meanbkdinter = 0
    else:
        dat.meanbkdinter = (dat.lasbkd_ts-dat.fbkd_ts)/(dat.bdp-1)
    
    outputFeature = str(key[0])+","+str(key[1])+","+str(key[2])+","+str(key[3])+","+str(dat.meanintertime)+","+str(dat.fdp)+","+str(dat.bdp)+","+str(dat.fwdbytes)+","+str(dat.bkdbytes)+","+str(dat.totdata)+","+str(dat.pktsmall)+","+str(dat.pktlarge)+","+str(dat.mxintertime)+"," +str(dat.mnintertime)+","+str(dat.totalduration)+","+str(dat.meanpkttime)+","+str(dat.meanfwdinter)+"," +str(dat.meanbkdinter)+","+str(dat.mxfwdintertime)+","+str(dat.mxbkdintertime)+","+str(dat.mnfwdintertime)+","+str(dat.mnbkdintertime)+"\n"
    return outputFeature
    

flow_dat={}
#ip_chk =['66.154.80.101','66.154.80.101','66.154.80.125','66.154.80.105','66.154.83.107','66.154.83.113','66.154.83.138','66.154.83.80','66.154.87.39','66.154.87.41','66.154.87.57','66.154.87.58','66.154.87.61']
ip_chk = ['192.168.1.2']

fl='/home/amit/botnet/data/abc2.pcap'
dns_res = set()

#cap = pyshark.FileCapture(fl,display_filter='ip.version==4')

f_pack = True
window = 3500

folder="/home/amit/botnet/data/brett_dumps/p2pbox1/box2/"
cnt=1
for x in os.listdir(folder):		
	fl=folder+x
	print x+" "+str(cnt)
	cap = pyshark.FileCapture(fl,display_filter='ip.version==4')
	f_pack = True
	dns_res.clear()
	flow_dat.clear()
	for pkt in cap:
	    if f_pack:
		st_time=int(float(pkt.sniff_timestamp))
		f_pack=False
	    else:
		end_time=int(float(pkt.sniff_timestamp))
		    #print st_time,end_time
		if end_time-st_time>=window:
		    f = open("/home/amit/botnet/data/bot_data/new_f/p2pbox1box2_all.csv","a")                               
		    for x in flow_dat.keys():                    
		        f.write(extractFeatures(x))      
		    f.close()
		    st_time = end_time
		    flow_dat = {}
	    if(("DNS" in str(pkt.layers)) ) or (("MDNS" in str(pkt.layers))):            
		str_pkt=str(pkt.layers[-1])
		res_ips = re.findall(r"addr\s(.*)", str_pkt)
		for x in res_ips:
		    if is_ipv4(x):
		        dns_res.add(x)
	    elif pkt.ip.src in dns_res or pkt.ip.dst in dns_res:
		continue
	    else:
		#print pkt.number
		HandlePacket(pkt)
	cnt+=1
